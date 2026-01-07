import * as Misskey from '@nexirift/pulsar-js';
import { cache } from './cache';
import { NotificationManager } from '../notifiers';
import EventEmitter from 'events';

export interface UserPollerOptions {
    instanceUrl: string;
    token: string;
    pollInterval?: number; // in milliseconds
    limit?: number; // number of users to fetch per poll
}

export class UserPoller extends EventEmitter {
    private client: Misskey.api.APIClient;
    private pollTimer: NodeJS.Timeout | null = null;
    private isRunning = false;
    private lastPolledTimestamp: Date | null = null;
    private notifications: NotificationManager;
    private startupTime: number;

    constructor(
        private options: UserPollerOptions,
        notifications: NotificationManager
    ) {
        super();
        this.client = new Misskey.api.APIClient({
            origin: options.instanceUrl,
            credential: options.token
        });
        this.notifications = notifications;
        this.startupTime = Date.now();
    }

    /**
     * Start polling for new users
     */
    async start(): Promise<void> {
        if (this.isRunning) {
            console.warn('User poller is already running');
            return;
        }

        this.isRunning = true;
        console.log('User poller started - tracking users created after startup');

        // Set up interval polling
        const interval = this.options.pollInterval || 60000; // Default: 1 minute
        this.pollTimer = setInterval(() => {
            this.pollUsers().catch(console.error);
        }, interval);
    }

    /**
     * Poll for new users
     */
    private async pollUsers(): Promise<void> {
        try {
            const limit = this.options.limit || 20;

            // Fetch recent users (newest first)
            const users = await this.client.request('users', {
                limit,
                sort: '-createdAt' as any,
                origin: 'local' as any
            });

            const newUsers: any[] = [];

            for (const user of users) {
                // Skip users created before bot started
                const userCreatedAt = new Date(user.createdAt).getTime();
                if (userCreatedAt < this.startupTime) {
                    continue;
                }

                // Check if we've seen this user before
                const cachedUser = cache.getUser(user.id);

                if (!cachedUser) {
                    // New user detected
                    newUsers.push(user);

                    // Cache the user
                    cache.setUser(user.id, {
                        ...user,
                        firstSeenAt: Date.now()
                    });

                    // Emit new user event
                    this.emit('newUser', user);

                    // Generate URLs
                    const userUrl = `${this.options.instanceUrl}/@${user.username}`;
                    const adminUrl = `${this.options.instanceUrl}/admin/user/${user.id}`;

                    console.log(`\n👤 [NEW USER] @${user.username}`);
                    console.log(`   ID: ${user.id}`);
                    console.log(`   Created: ${user.createdAt}`);
                    console.log(`   Profile: ${userUrl}`);
                    console.log(`   Admin: ${adminUrl}`);

                    // Send notification
                    await this.notifications.notify({
                        type: 'new_user',
                        severity: 'low',
                        title: '👤 New User Detected',
                        description: `**User:** @${user.username}\n**Created:** <t:${Math.floor(new Date(user.createdAt).getTime() / 1000)}:R>`,
                        metadata: {
                            'User ID': user.id,
                            'Username': `@${user.username}`,
                            'Created At': user.createdAt,
                            'Is Bot': user.isBot ? 'Yes' : 'No',
                            'Profile URL': userUrl,
                            'Admin Panel': adminUrl
                        },
                        timestamp: new Date()
                    });
                } else if (user.updatedAt && cachedUser.updatedAt !== user.updatedAt) {
                    // User was updated
                    cache.setUser(user.id, {
                        ...user,
                        lastUpdatedAt: Date.now()
                    });

                    this.emit('userUpdated', user);
                }
            }

            if (newUsers.length > 0) {
                console.log(`Found ${newUsers.length} new user(s)`);
            }

            this.lastPolledTimestamp = new Date();
            this.emit('polled', { userCount: users.length, newUserCount: newUsers.length });

        } catch (error) {
            console.error('Error polling users:', error);
            this.emit('error', error);
        }
    }

    /**
     * Stop polling for users
     */
    async stop(): Promise<void> {
        if (!this.isRunning) {
            console.warn('User poller is not running');
            return;
        }

        if (this.pollTimer) {
            clearInterval(this.pollTimer);
            this.pollTimer = null;
        }

        this.isRunning = false;
        console.log('User poller stopped');
    }

    /**
     * Check if poller is running
     */
    isActive(): boolean {
        return this.isRunning;
    }

    /**
     * Get last polled timestamp
     */
    getLastPolledTime(): Date | null {
        return this.lastPolledTimestamp;
    }

    /**
     * Manually trigger a poll (outside of interval)
     */
    async triggerPoll(): Promise<void> {
        if (!this.isRunning) {
            throw new Error('User poller is not running');
        }
        await this.pollUsers();
    }
}
