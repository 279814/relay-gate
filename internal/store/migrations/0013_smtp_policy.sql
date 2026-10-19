ALTER TABLE smtp_config ADD COLUMN aggregation_window_sec INTEGER NOT NULL DEFAULT 300 CHECK (aggregation_window_sec BETWEEN 1 AND 86400);
ALTER TABLE smtp_config ADD COLUMN rate_limit_window_sec INTEGER NOT NULL DEFAULT 300 CHECK (rate_limit_window_sec BETWEEN 1 AND 86400);
ALTER TABLE smtp_config ADD COLUMN revision INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1);
