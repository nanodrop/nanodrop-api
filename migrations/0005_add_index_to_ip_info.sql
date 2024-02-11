-- Migration number: 0005 	 2024-02-11T23:17:30.033Z

-- Add index on the 'ip' column
CREATE INDEX ip_info_ip_index ON ip_info(ip);
