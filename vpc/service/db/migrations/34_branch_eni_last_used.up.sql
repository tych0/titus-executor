START TRANSACTION ;
alter table branch_enis
    add last_used timestamp not null default now();
COMMIT ;