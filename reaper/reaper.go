package reaper

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Netflix/titus-executor/models"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	docker "github.com/docker/docker/client"
	"github.com/hashicorp/go-multierror"
	"github.com/moby/sys/mountinfo"
	"github.com/sirupsen/logrus"
)

var (
	timeout = 30 * time.Second
)

// RunReaper runs reaper as a one-shot
func RunReaper(ctx context.Context, dockerHost string) error {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	client, err := docker.NewClientWithOpts(docker.WithHost(dockerHost))
	if err != nil {
		return fmt.Errorf("Cannot initialize docker client")
	}

	return reap(ctx, client)
}

func reap(ctx context.Context, dockerClient *docker.Client) error {
	filter := filters.NewArgs()
	filter.Add("status", "running")
	filter.Add("status", "paused")
	filter.Add("status", "exited")
	filter.Add("status", "dead")
	filter.Add("status", "created")

	containers, err := dockerClient.ContainerList(ctx, types.ContainerListOptions{Filters: filter, All: true})
	if err != nil {
		return fmt.Errorf("Unable to get containers: %w", err)
	}

	titusContainers := filterTitusContainers(containers)
	/* Now we have to inspect these to get the container JSON */
	var result *multierror.Error
	for _, container := range titusContainers {
		err = processContainer(ctx, container, dockerClient)
		if err != nil {
			result = multierror.Append(result, err)
		}
	}

	return result.ErrorOrNil()
}

func filterTitusContainers(containers []types.Container) []types.Container {
	ret := []types.Container{}
	for _, container := range containers {
		if _, ok := container.Labels[models.ExecutorPidLabel]; ok {
			if time.Since(time.Unix(container.Created, 0)) > 5*time.Minute {
				ret = append(ret, container)
			}
		}
	}
	return ret
}

func processContainer(ctx context.Context, container types.Container, dockerClient *docker.Client) error {
	logrus.WithField("container", container).Debug("Checking container")
	containerJSON, err := dockerClient.ContainerInspect(ctx, container.ID)
	if docker.IsErrNotFound(err) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("Unable to fetch container JSON: %w", err)
	}

	return processContainerJSON(ctx, containerJSON, dockerClient)
}

type client interface {
	ContainerStop(ctx context.Context, containerID string, timeout *time.Duration) error
	ContainerRemove(ctx context.Context, container string, options types.ContainerRemoveOptions) error
}

func processContainerJSON(ctx context.Context, container types.ContainerJSON, dockerClient client) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	taskID, ok := container.Config.Labels[models.TaskIDLabel]
	if !ok {
		return fmt.Errorf("Did not find task ID label on container %q", container.ID)
	}
	l := logrus.WithField("taskID", taskID)

	// We filter for this label in filterContainers above
	executorPid := container.Config.Labels[models.ExecutorPidLabel]

	exe := filepath.Join("/proc", executorPid, "exe")
	stat, err := os.Stat(exe)
	if os.IsNotExist(err) {
		var result *multierror.Error
		l.Info("Terminating container")
		if err := dockerClient.ContainerStop(ctx, container.ID, &timeout); err != nil {
			l.WithError(err).Warning("Unable to stop container")
			result = multierror.Append(result, fmt.Errorf("Unable to stop container %q: %w", container.ID, err))
		}
		if err := dockerClient.ContainerRemove(ctx, container.ID, types.ContainerRemoveOptions{Force: true, RemoveVolumes: true}); err != nil {
			l.WithError(err).Warning("Unable to remove container")
			result = multierror.Append(result, fmt.Errorf("Unable to remove container %q: %w", container.ID, err))
		}
		err = result.ErrorOrNil()
		if err != nil {
			l.WithError(err).Error("Unable to terminate container")
		}
		return err
	}

	if err != nil {
		l.WithError(err).Error("Unable to determine if container is running or not")
		return fmt.Errorf("Unable to determine if container is running or not: %w", err)
	}

	link, err := os.Readlink(exe)
	if err != nil {
		l.WithError(err).Error("Could not readlink exe path")
		return fmt.Errorf("Could not readlink exe path: %w", err)
	}

	if !strings.HasPrefix(link, "/apps/titus-executor") {
		l.WithField("exe", exe).Warning("Could not determine is process is titus executor")
		return fmt.Errorf("Could not determine whether or not process with exe %q / and stat %v was a titus executor", link, stat)
	}

	l.WithFields(map[string]interface{}{
		"link": link,
		"exe":  exe,
		"stat": stat,
	}).Debug("Processed container and found consistent state")

	return nil
}

// there is a kernel bug described in:
// https://lore.kernel.org/all/YrShFXRLtRt6T%2Fj+@risky/ where fuse can cause a
// pidns exit to deadlock. They symptoms are:
//
//    1. pidns pid 1 in S (sleeping) state
//    2. that pid has zap_pid_ns_processes() in its /proc/pid/stack
//    3. some fuse mount exists, and one of the threads from that fuse mount is
//       stuck in fuse_flush()
//
// if those conditions are true, we need to manually tear down the fuse
// connection so the pidns can exit and docker doesn't get stuck. we can do
// this by writing something to
//
// 	/sys/fs/fuse/connections/$dev_minor/abort
//
// where $dev_minor is the minor number from the fuse superblock mount.
func checkIfFuseWedgedPidNs(pid int) {
	if !kernelStackHas(pid, "zap_pid_ns_processes") {
		return
	}

	// the kernel has already destroyed the mountinfo for the pidns' init,
	// since it is pretty far along in do_exit(). we need to keep the tid
	// of the fuse process around so we can inspect its mountinfo instead.
	//
	// ideally we'd use the pids cgroup (i.e. the docker API) here to
	// figure out what tasks we should look at, but that *also* has been
	// invalidated and is incorrect at this point. luckily for us the fuse
	// daemon that's causing this hang in our production case is a child of
	// init, so we can just look at that. as a bonus, this file outputs
	// tids instead of pids, so we don't have to do any additional parsing.
	targetTid := 0
	for _, tid := range childThreadsOfPid(pid) {
		if kernelStackHas(tid, "fuse_flush") {
			targetTid = tid
			break
		}
	}
	if targetTid == 0 {
		return
	}

	// walk the mountinfo for the container and get the superblock minor
	// number. let's just manually kill any existing fuse thing, since the
	// pid ns is dying anyway.
	infos, err := mountinfo.PidMountInfo(targetTid)
	if err != nil {
		logrus.Errorf("failed getting mount info for %d: %v", targetTid, err)
		return
	}

	for _, m := range infos {
		if !strings.HasPrefix(m.FSType, "fuse") {
			continue
		}

		err = ioutil.WriteFile(fmt.Sprintf("/sys/fs/fuse/connections/%d/abort", m.Minor), []byte("foo"), 0755)
		if err != nil {
			logrus.Errorf("failed killing fuse connection %d: %v", m.Minor, err)
		}
	}
}

func kernelStackHas(pid int, function string) bool {
	content, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/stack", pid))
	if err != nil {
		logrus.Errorf("couldn't read kernel stack file for %d: %v", pid, err)
		return false
	}

	// the format of this file has changed somewhat over time; here's a
	// reasonable guess at e.g.
	//      [<0>] vfs_read+0x9c/0x1a0
	return strings.Contains(string(content), function+"+0x")
}

func childThreadsOfPid(pid int) []int {
	// "children" doesn't exist in /proc/pid for some reason...
	threadsRaw, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/task/%d/children", pid))
	if err != nil {
		logrus.Errorf("couldn't read task dir for %d: %v", pid, err)
		return nil
	}

	threads := []int{}
	for _, e := range strings.Fields(string(threadsRaw)) {
		tid, err := strconv.Atoi(e)
		if err != nil {
			logrus.Errorf("couldn't read task dir for %d: %v", pid, err)
			return nil
		}
		threads = append(threads, tid)
	}

	return threads
}
