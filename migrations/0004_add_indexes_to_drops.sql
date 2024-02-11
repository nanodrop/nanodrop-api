-- Migration number: 0004 	 2024-02-11T20:30:44.911Z

-- Add index on the 'ip' column
CREATE INDEX drops_ip_index ON drops(ip);

-- Add index on the 'account' column
CREATE INDEX drops_account_index ON drops(account);

-- Add index on the 'timestamp' column
CREATE INDEX drops_timestamp_index ON drops(timestamp);
