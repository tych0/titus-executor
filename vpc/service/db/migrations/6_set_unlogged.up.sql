START TRANSACTION;
ALTER TABLE ip_last_used SET UNLOGGED;
ALTER TABLE branch_eni_last_used SET UNLOGGED;
COMMIT;