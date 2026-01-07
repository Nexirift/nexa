import "dotenv/config";

import { createEnv } from "@t3-oss/env-core";
import { z } from "zod";

export const env = createEnv({
    server: {
        NODE_ENV: z.enum(["development", "production", "test"]).default("development"),
        INSTANCE_URL: z.url(),
        INSTANCE_TOKEN: z.string(),
        INSTANCE_AUTOMOD: z.string().optional(), // Skip events by this user (e.g., bot's own username)

        // Discord notifications
        DISCORD_WEBHOOK_URL: z.url().optional(),

        // User polling settings
        USER_POLL_INTERVAL: z.coerce.number().default(30000), // milliseconds, default 30 seconds
        USER_POLL_LIMIT: z.coerce.number().default(50), // number of users to fetch per poll

        // Detection thresholds
        NSFW_THRESHOLD: z.coerce.number().min(0).max(1).default(0.7),
        SPAM_SCORE_THRESHOLD: z.coerce.number().default(2),
        PHISHING_SCORE_THRESHOLD: z.coerce.number().default(2),

        // Virus Detection Settings
        VIRUS_SCAN_FILES: z.coerce.boolean().default(true),
        VIRUS_SCAN_LINKS: z.coerce.boolean().default(true),
        VIRUS_CLAMAV_ENABLED: z.coerce.boolean().default(true),
        VIRUS_CLAMAV_SOCKET: z.string().default('/var/run/clamav/clamd.ctl'),
        VIRUS_CLAMAV_HOST: z.string().optional(),
        VIRUS_CLAMAV_PORT: z.coerce.number().optional(),
        VIRUS_MAX_FILE_SIZE: z.coerce.number().default(100 * 1024 * 1024), // 100MB
        VIRUS_MAX_FILES_PER_NOTE: z.coerce.number().default(20),
        VIRUS_MAX_LINKS_PER_NOTE: z.coerce.number().default(50),
        VIRUS_AUTO_DELETE: z.coerce.boolean().default(true),
        VIRUS_AUTO_DELETE_SUSPICIOUS: z.coerce.boolean().default(false),
        VIRUS_DELETE_FILES: z.coerce.boolean().default(true),
        VIRUS_DELETE_NOTE: z.coerce.boolean().default(true),
        VIRUS_QUARANTINE: z.coerce.boolean().default(true),
        VIRUS_SUSPEND_USER: z.coerce.boolean().default(false),
        VIRUS_SUSPEND_THRESHOLD: z.coerce.number().default(3),
        VIRUS_SILENCE_USER: z.coerce.boolean().default(false),
        VIRUS_SILENCE_DURATION: z.coerce.number().default(24 * 60 * 60 * 1000), // 24h
        VIRUS_TRACK_USER_HISTORY: z.coerce.boolean().default(true),
        VIRUS_CACHE_TTL: z.coerce.number().default(90 * 24 * 60 * 60), // 90 days
        VIRUS_SCAN_TIMEOUT: z.coerce.number().default(30000), // 30s
        VIRUS_DOWNLOAD_TIMEOUT: z.coerce.number().default(30000), // 30s
        VIRUS_NOTIFY_CONFIRMED: z.coerce.boolean().default(true),
        VIRUS_NOTIFY_SUSPICIOUS: z.coerce.boolean().default(true),
        VIRUS_NOTIFY_GROUP_BY_USER: z.coerce.boolean().default(true),
        VIRUS_NOTIFY_GROUPING_WINDOW: z.coerce.number().default(5 * 60 * 1000), // 5 min
        VIRUS_LOG_VERBOSE: z.coerce.boolean().default(false),
        VIRUS_LOG_STATS: z.coerce.boolean().default(true),
        VIRUS_STATS_INTERVAL: z.coerce.number().default(60 * 60 * 1000), // 1 hour
    },

    /**
     * What object holds the environment variables at runtime. This is usually
     * `process.env` or `import.meta.env`.
     */
    runtimeEnv: process.env,

    /**
     * By default, this library will feed the environment variables directly to
     * the Zod validator.
     *
     * This means that if you have an empty string for a value that is supposed
     * to be a number (e.g. `PORT=` in a ".env" file), Zod will incorrectly flag
     * it as a type mismatch violation. Additionally, if you have an empty string
     * for a value that is supposed to be a string with a default value (e.g.
     * `DOMAIN=` in an ".env" file), the default value will never be applied.
     *
     * In order to solve these issues, we recommend that all new projects
     * explicitly specify this option as true.
     */
    emptyStringAsUndefined: true,
});