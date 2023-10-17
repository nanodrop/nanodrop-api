-- Migration number: 0003 	 2023-10-15T10:37:52.211Z

CREATE TABLE IF NOT EXISTS drops_by_country (
    country_code VARCHAR(2) NOT NULL,
    count INT NOT NULL,
    PRIMARY KEY (country_code)
);

-- Add trigger
CREATE TRIGGER IF NOT EXISTS update_drops_by_country
AFTER INSERT ON drops
BEGIN
    INSERT OR REPLACE INTO drops_by_country (country_code, count)
    VALUES (
        (SELECT country_code FROM ip_info WHERE ip = NEW.ip),
        COALESCE((SELECT count FROM drops_by_country WHERE country_code = (SELECT country_code FROM ip_info WHERE ip = NEW.ip)), 0) + 1
    );
END;

-- Create a temporary table to hold the existing data
CREATE TEMP TABLE TempDrops AS SELECT * FROM drops;

-- Clear the original table
DELETE FROM drops;

-- Re-insert the data to trigger the update_drops_by_country
INSERT INTO drops SELECT * FROM TempDrops;

-- Delete the temporary table
DROP TABLE TempDrops;