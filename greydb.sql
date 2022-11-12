CREATE TABLE pending (
ip varchar(15),
envsender varchar,
envrecipient varchar,
tsfirstdelivery timestamp,
tslastdelivery timestamp,
attempts smallint,
primary key (ip,envsender,envrecipient)
);
-- CREATE UNIQUE INDEX pendingip_index ON pending (ip);
CREATE TABLE verified (
ip varchar(15) primary key,
ts timestamp
);
CREATE UNIQUE INDEX verifiedip_index ON verified (ip);

