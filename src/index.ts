import { env } from "./env";
import { ConsoleNotifier, DiscordNotifier, NotificationManager } from "./notifiers";
import { initCache } from "./modules/cache";
import { TimelineListener, UserPoller } from "./modules";
import { NSFWDetectionService } from "./services/nsfw-detection";
import { VirusDetectionService } from "./services/virus-detection";
import { SpamDetectionService } from "./services/spam-detection";
import { PhishingDetectionService } from "./services/phishing-detection";
import { ModeratorLogMonitorService } from "./services/moderator-log-monitor";
import * as Misskey from "@nexirift/pulsar-js";

class AutoModerator {
    private client: Misskey.api.APIClient;
    private notifications: NotificationManager;
    private timelineListener: TimelineListener;
    private userPoller: UserPoller;

    // Detection services
    private nsfwDetection!: NSFWDetectionService;
    private virusDetection!: VirusDetectionService;
    private spamDetection!: SpamDetectionService;
    private phishingDetection!: PhishingDetectionService;
    private moderatorLogMonitor!: ModeratorLogMonitorService;

    constructor() {
        this.client = new Misskey.api.APIClient({
            origin: env.INSTANCE_URL,
            credential: env.INSTANCE_TOKEN,
        });

        this.notifications = new NotificationManager();

        // Initialize modules
        this.timelineListener = new TimelineListener(
            {
                instanceUrl: env.INSTANCE_URL,
                token: env.INSTANCE_TOKEN,
                channels: ['global']
            },
            this.notifications
        );

        this.userPoller = new UserPoller(
            {
                instanceUrl: env.INSTANCE_URL,
                token: env.INSTANCE_TOKEN,
                pollInterval: env.USER_POLL_INTERVAL,
                limit: env.USER_POLL_LIMIT
            },
            this.notifications
        );
    }

    async initialize(): Promise<void> {
        // Setup notifications
        this.notifications.addNotifier(new ConsoleNotifier());
        if (env.DISCORD_WEBHOOK_URL) {
            this.notifications.addNotifier(new DiscordNotifier(env.DISCORD_WEBHOOK_URL));
        }

        // Initialize cache
        await initCache();

        // Connect to instance
        const meta = await this.client.request('meta');
        console.log('Connected to instance:', meta.name ?? new URL(meta.uri).host);

        // Initialize detection services
        this.nsfwDetection = new NSFWDetectionService(
            this.timelineListener,
            this.notifications,
            { threshold: env.NSFW_THRESHOLD, autoFlag: true, scanImages: true, scanText: true, instanceUrl: env.INSTANCE_URL }
        );

        this.virusDetection = new VirusDetectionService(
            this.client,
            this.timelineListener,
            this.notifications,
            { useEnvConfig: true, instanceUrl: env.INSTANCE_URL }
        );

        this.spamDetection = new SpamDetectionService(
            this.timelineListener,
            this.notifications,
            {
                checkRepeatedContent: true,
                checkUrls: true,
                checkMentions: true,
                maxPostsPerWindow: 5,
                instanceUrl: env.INSTANCE_URL
            }
        );

        this.phishingDetection = new PhishingDetectionService(
            this.timelineListener,
            this.notifications,
            {
                checkUrls: true,
                checkSuspiciousKeywords: true,
                blockKnownPhishing: true,
                instanceUrl: env.INSTANCE_URL
            }
        );

        this.moderatorLogMonitor = new ModeratorLogMonitorService(
            this.client,
            this.notifications,
            {
                pollInterval: 30 * 1000, // Check every 30 seconds
                instanceUrl: env.INSTANCE_URL,
                automodUser: env.INSTANCE_AUTOMOD
            }
        );

        // Start modules
        await this.timelineListener.start();
        await this.userPoller.start();
        await this.moderatorLogMonitor.start();

        console.log('AutoModerator initialized successfully');
        console.log('Active detection services: NSFW, Virus, Spam, Phishing');
        console.log('Moderator log monitoring: Enabled');

        // Log combined stats every 30 seconds
        setInterval(() => {
            const nsfwStats = this.nsfwDetection.getStats();
            const virusStats = this.virusDetection.getStats();
            const spamStats = this.spamDetection.getStats();
            const phishingStats = this.phishingDetection.getStats();
            const moderatorStats = this.moderatorLogMonitor.getStats();

            console.log(`\n📊 [DETECTION STATS]`);
            console.log(`   NSFW:     ${nsfwStats.scanned} scanned, ${nsfwStats.detected} detected`);
            console.log(`   Virus:    ${virusStats.scanned} scanned, ${virusStats.detected} detected`);
            console.log(`   Spam:     ${spamStats.scanned} scanned, ${spamStats.detected} detected`);
            console.log(`   Phishing: ${phishingStats.scanned} scanned, ${phishingStats.detected} detected`);
            console.log(`   Resolved: ${moderatorStats.resolved} issues resolved`);
            if (moderatorStats.lateResponses > 0) {
                console.log(`   ⚠️  Late:    ${moderatorStats.lateResponses} responses >24h`);
            }
            if (moderatorStats.ignoredSelfActions > 0) {
                console.log(`   Ignored:  ${moderatorStats.ignoredSelfActions} self-actions`);
            }
            if (moderatorStats.ignoredAutomodActions > 0) {
                console.log(`   Skipped:  ${moderatorStats.ignoredAutomodActions} automod actions`);
            }
        }, 30000);
    }

    async shutdown(): Promise<void> {
        console.log('Shutting down AutoModerator...');
        this.moderatorLogMonitor.stop();
        await this.timelineListener.stop();
        await this.userPoller.stop();
        console.log('AutoModerator shutdown complete');
    }
}

// Start the moderator
const moderator = new AutoModerator();
moderator.initialize().catch(console.error);

// Graceful shutdown
process.on('SIGINT', async () => {
    await moderator.shutdown();
    process.exit(0);
});

process.on('SIGTERM', async () => {
    await moderator.shutdown();
    process.exit(0);
});
