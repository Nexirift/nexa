import * as Misskey from '@nexirift/pulsar-js';
import { TimelineListener } from '../modules/timeline-listener';
import { UserPoller } from '../modules/user-poller';
import { cache } from '../modules/cache';
import { NotificationManager } from '../notifiers';

export interface ContentModerationOptions {
    autoBlock?: boolean;
    checkNSFW?: boolean;
    checkSpam?: boolean;
    minAccountAge?: number; // in milliseconds
}

/**
 * Sample service demonstrating how to receive and process new posts and users
 */
export class ContentModerationService {
    private processedNotesCount = 0;
    private processedUsersCount = 0;
    private flaggedContent = 0;

    constructor(
        private timelineListener: TimelineListener,
        private userPoller: UserPoller,
        private notifications: NotificationManager,
        private options: ContentModerationOptions = {}
    ) {
        this.setupListeners();
    }

    /**
     * Set up event listeners for new content
     */
    private setupListeners(): void {
        // Listen for new posts/notes
        this.timelineListener.on('note', (note: Misskey.entities.Note, channel: string) => {
            this.handleNewNote(note, channel);
        });

        // Listen for new users
        this.userPoller.on('newUser', (user: any) => {
            this.handleNewUser(user);
        });

        // Listen for user updates
        this.userPoller.on('userUpdated', (user: any) => {
            this.handleUserUpdate(user);
        });

        console.log('Content Moderation Service initialized and listening for events');
    }

    /**
     * Handle new note/post - called immediately when received
     */
    private async handleNewNote(note: Misskey.entities.Note, channel: string): Promise<void> {
        this.processedNotesCount++;

        console.log(`\n📝 [MODERATION] Processing note #${this.processedNotesCount}`);
        console.log(`   Channel: ${channel}`);
        console.log(`   From: @${note.user.username}`);
        console.log(`   Text: ${note.text?.substring(0, 100) || '(no text)'}...`);

        // Example: Check for spam patterns
        if (this.options.checkSpam && this.isSpamLike(note)) {
            await this.flagContent(note, 'spam');
        }

        // Example: Check for NSFW content
        if (this.options.checkNSFW && note.files && note.files.length > 0) {
            console.log(`   ⚠️  Note contains ${note.files.length} file(s) - would scan for NSFW`);
            // Here you would call NSFW detection service
        }

        // Example: Check user account age
        const userAge = Date.now() - new Date(note.user.createdAt!).getTime();
        const minAge = this.options.minAccountAge || 24 * 60 * 60 * 1000; // 24 hours default

        if (userAge < minAge) {
            console.log(`   ⚠️  New account (${Math.floor(userAge / (60 * 60 * 1000))} hours old)`);
        }

        // Example: Store in custom tracking
        this.trackNoteActivity(note);
    }

    /**
     * Handle new user - called immediately when detected
     */
    private async handleNewUser(user: any): Promise<void> {
        this.processedUsersCount++;

        console.log(`\n👤 [MODERATION] New user detected #${this.processedUsersCount}`);
        console.log(`   Username: @${user.username}`);
        console.log(`   ID: ${user.id}`);
        console.log(`   Created: ${user.createdAt}`);
        console.log(`   Is Bot: ${user.isBot}`);
        console.log(`   Is Cat: ${user.isCat}`);

        // Example: Check for suspicious patterns
        if (this.isSuspiciousUsername(user.username)) {
            await this.flagUser(user, 'suspicious_username');
        }

        // Example: Send welcome message or initiate monitoring
        console.log(`   ✅ Starting monitoring for @${user.username}`);

        // Notify about new user
        await this.notifications.notify({
            type: 'new_user',
            severity: 'low',
            title: 'New User Joined',
            description: `@${user.username} has joined the instance`,
            metadata: {
                userId: user.id,
                username: user.username,
                isBot: user.isBot
            },
            timestamp: new Date()
        });
    }

    /**
     * Handle user updates
     */
    private async handleUserUpdate(user: any): Promise<void> {
        console.log(`\n🔄 [MODERATION] User updated: @${user.username}`);

        // Example: Check for profile changes
        const cached = cache.getUser(user.id);
        if (cached) {
            if (cached.username !== user.username) {
                console.log(`   ⚠️  Username changed: ${cached.username} -> ${user.username}`);
            }
            if (cached.description !== user.description) {
                console.log(`   📝 Bio updated`);
            }
        }
    }

    /**
     * Example spam detection
     */
    private isSpamLike(note: Misskey.entities.Note): boolean {
        if (!note.text) return false;

        const spamPatterns = [
            /(?:https?:\/\/[^\s]+){3,}/i, // Multiple URLs
            /(.)\1{10,}/, // Repeated characters
            /BUY NOW|CLICK HERE|FREE MONEY/i, // Spam keywords
        ];

        return spamPatterns.some(pattern => pattern.test(note.text!));
    }

    /**
     * Example suspicious username detection
     */
    private isSuspiciousUsername(username: string): boolean {
        const suspiciousPatterns = [
            /admin/i,
            /moderator/i,
            /^[a-z]{1,2}\d{5,}$/, // Short letters followed by many numbers
            /casino|gambling|crypto|nft/i
        ];

        return suspiciousPatterns.some(pattern => pattern.test(username));
    }

    /**
     * Flag content for review
     */
    private async flagContent(note: Misskey.entities.Note, reason: string): Promise<void> {
        this.flaggedContent++;

        console.log(`   🚩 FLAGGED: ${reason}`);

        await this.notifications.notify({
            type: 'spam_detected',
            severity: 'medium',
            title: 'Potential Spam Detected',
            description: `Note from @${note.user.username} flagged as ${reason}`,
            metadata: {
                noteId: note.id,
                userId: note.user.id,
                reason,
                text: note.text?.substring(0, 200)
            },
            timestamp: new Date()
        });

        // Store flag in cache
        cache.set(`flag:${note.id}`, {
            noteId: note.id,
            userId: note.user.id,
            reason,
            flaggedAt: Date.now()
        }, 7 * 24 * 60 * 60); // 7 days TTL
    }

    /**
     * Flag user for review
     */
    private async flagUser(user: any, reason: string): Promise<void> {
        console.log(`   🚩 USER FLAGGED: ${reason}`);

        await this.notifications.notify({
            type: 'new_user',
            severity: 'medium',
            title: 'Suspicious User Detected',
            description: `User @${user.username} flagged as ${reason}`,
            metadata: {
                userId: user.id,
                username: user.username,
                reason
            },
            timestamp: new Date()
        });
    }

    /**
     * Track note activity for analysis
     */
    private trackNoteActivity(note: Misskey.entities.Note): void {
        const userId = note.user.id;
        const activityKey = `activity:${userId}`;

        // Get or initialize user activity
        const activity = cache.get<any>(activityKey) || {
            userId,
            username: note.user.username,
            noteCount: 0,
            lastNoteAt: null,
            recentNotes: []
        };

        activity.noteCount++;
        activity.lastNoteAt = Date.now();
        activity.recentNotes.unshift({
            noteId: note.id,
            text: note.text?.substring(0, 50),
            createdAt: note.createdAt
        });

        // Keep only last 10 notes
        activity.recentNotes = activity.recentNotes.slice(0, 10);

        // Store with 1 hour TTL
        cache.set(activityKey, activity, 60 * 60);
    }

    /**
     * Get service statistics
     */
    getStats() {
        return {
            processedNotes: this.processedNotesCount,
            processedUsers: this.processedUsersCount,
            flaggedContent: this.flaggedContent,
            uptime: process.uptime()
        };
    }

    /**
     * Get user activity summary
     */
    getUserActivity(userId: string) {
        return cache.get(`activity:${userId}`);
    }
}
