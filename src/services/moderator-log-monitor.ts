import * as Misskey from '@nexirift/pulsar-js';
import { cache } from '../modules/cache';
import { NotificationManager } from '../notifiers';

export interface ModeratorLogMonitorOptions {
    pollInterval?: number; // milliseconds
    instanceUrl?: string;
    automodUser?: string; // Username to ignore (bot's own username)
}

interface ModerationLogEntry {
    id: string;
    createdAt: string;
    type: string;
    info: {
        noteId?: string;
        userId?: string;
        fileId?: string;
        [key: string]: any;
    };
    userId: string;
    user: Misskey.entities.UserLite;
}

/**
 * Moderator Log Monitor Service
 * Watches for moderator actions and correlates them with detected issues
 */
export class ModeratorLogMonitorService {
    private pollTimer?: NodeJS.Timeout;
    private lastCheckedId?: string;
    private resolvedCount = 0;
    private ignoredSelfActions = 0;
    private ignoredAutomodActions = 0;
    private lateResponses = 0;
    private readonly LATE_RESPONSE_THRESHOLD = 24 * 60 * 60 * 1000; // 24 hours

    constructor(
        private client: Misskey.api.APIClient,
        private notifications: NotificationManager,
        private options: ModeratorLogMonitorOptions = {}
    ) {
        this.options = {
            pollInterval: 30 * 1000, // 30 seconds
            ...options
        };
    }

    async start(): Promise<void> {
        console.log('Moderator Log Monitor started');

        // Do initial check
        await this.checkModeratorLog();

        // Start polling
        this.pollTimer = setInterval(() => {
            this.checkModeratorLog().catch(err => {
                console.error('Error checking moderator log:', err);
            });
        }, this.options.pollInterval);
    }

    stop(): void {
        if (this.pollTimer) {
            clearInterval(this.pollTimer);
            this.pollTimer = undefined;
        }
        console.log('Moderator Log Monitor stopped');
    }

    private async checkModeratorLog(): Promise<void> {
        try {
            // Fetch recent moderation log entries
            // Note: This endpoint requires admin permissions with read:admin:show-moderation-log
            const logs = await this.client.request('admin/show-moderation-logs', {
                limit: 50,
            }) as ModerationLogEntry[];

            if (logs.length === 0) return;

            // Track the most recent entry
            const mostRecentId = logs[0].id;

            // Process new entries (those we haven't seen before)
            const newEntries = this.lastCheckedId
                ? logs.filter(log => log.id > this.lastCheckedId!)
                : logs;

            for (const entry of newEntries) {
                await this.processLogEntry(entry);
            }

            this.lastCheckedId = mostRecentId;
        } catch (error) {
            // If we don't have admin permissions, fail gracefully
            if ((error as any)?.code === 'PERMISSION_DENIED') {
                console.warn('⚠️ Moderator log monitoring disabled: insufficient permissions');
                this.stop();
            } else {
                console.error('Error fetching moderator log:', error);
            }
        }
    }

    private async processLogEntry(entry: ModerationLogEntry): Promise<void> {
        // Check if this log entry relates to any of our detections
        // entry.info.userId = affected user (who had action taken against them)
        // entry.userId = moderator (who took the action)
        const { noteId, userId: affectedUserId, fileId } = entry.info;

        // Ignore actions by the automod user itself (to avoid self-reporting)
        if (this.options.automodUser && entry.user.username === this.options.automodUser) {
            this.ignoredAutomodActions++;
            return;
        }

        // Ignore self-actions (when moderator takes action on their own content)
        if (affectedUserId && entry.userId === affectedUserId) {
            this.ignoredSelfActions++;
            return;
        }

        // Check all detection types
        const detectionTypes = ['nsfw', 'spam', 'phishing', 'virus'] as const;

        for (const type of detectionTypes) {
            // Check note-based detections
            if (noteId) {
                const cacheKey = `${type}:${noteId}`;
                const detection = cache.get<any>(cacheKey);

                if (detection && !detection.resolved) {
                    await this.handleResolution(type, entry, detection, cacheKey, 'note');
                }
            }

            // Check user-based detections
            // If a moderator action is taken against a user, check if we have any detections for that user
            if (affectedUserId && !noteId && this.isUserAction(entry.type)) {
                // Look for detections from the affected user
                const userDetections = this.findDetectionsByUser(type, affectedUserId);
                for (const { detection, key } of userDetections) {
                    if (!detection.resolved) {
                        await this.handleResolution(type, entry, detection, key, 'user');
                    }
                }
            }

            // Check file-based detections (mainly for virus)
            if (fileId && type === 'virus') {
                const fileDetectionKey = `virus:file:${fileId}`;
                const noteId = cache.get<string>(fileDetectionKey);
                if (noteId) {
                    const cacheKey = `virus:${noteId}`;
                    const detection = cache.get<any>(cacheKey);
                    if (detection && !detection.resolved) {
                        await this.handleResolution('virus', entry, detection, cacheKey, 'file');
                    }
                }
            }
        }
    }

    private isUserAction(actionType: string): boolean {
        const userActions = [
            'suspendUser',
            'unsuspendUser',
            'silenceUser',
            'unsilenceUser',
            'forceAdultsOnly',
            'resetPassword',
            'deleteAccount'
        ];
        return userActions.includes(actionType);
    }

    private findDetectionsByUser(type: string, userId: string): Array<{ detection: any; key: string }> {
        const results: Array<{ detection: any; key: string }> = [];

        // Get the list of note IDs for this user's detections
        const userNotesKey = `${type}:user:${userId}:notes`;
        const noteIds = cache.get<string[]>(userNotesKey);

        if (noteIds?.length) {
            // Look up each detection by note ID
            for (const noteId of noteIds) {
                const cacheKey = `${type}:${noteId}`;
                const detection = cache.get<any>(cacheKey);
                if (detection?.userId === userId) {
                    results.push({ detection, key: cacheKey });
                }
            }
        }

        return results;
    }

    private async handleResolution(
        detectionType: string,
        logEntry: ModerationLogEntry,
        detection: any,
        cacheKey: string,
        actionContext: 'note' | 'user' | 'file'
    ): Promise<void> {
        this.resolvedCount++;

        const action = this.getActionDescription(logEntry.type);
        const moderator = logEntry.user.username;

        // Calculate response time
        const detectionTime = detection.detectedAt;
        const actionTime = new Date(logEntry.createdAt).getTime();
        const responseTime = actionTime - detectionTime;
        const isLateResponse = responseTime > this.LATE_RESPONSE_THRESHOLD;

        if (isLateResponse) {
            this.lateResponses++;
        }

        // Generate URLs
        const noteUrl = detection.noteUrl || 'N/A';
        const userUrl = detection.userUrl || 'N/A';

        const contextMessage = actionContext === 'user'
            ? `User-level action taken`
            : actionContext === 'file'
                ? `File action taken`
                : `Note-level action taken`;

        const responseTimeFormatted = this.formatResponseTime(responseTime);
        const lateFlag = isLateResponse ? ' ⚠️ LATE RESPONSE (>24h)' : '';

        console.log(`\n✅ [RESOLVED] ${detectionType.toUpperCase()} detection potentially resolved (${contextMessage})${lateFlag}`);
        console.log(`   Note ID: ${detection.noteId}`);
        console.log(`   User: @${detection.username}`);
        console.log(`   Action: ${action}`);
        console.log(`   Moderator: @${moderator}`);
        console.log(`   Response Time: ${responseTimeFormatted}`);

        // Mark as resolved in cache
        cache.set(cacheKey, {
            ...detection,
            resolved: true,
            resolvedAt: actionTime,
            resolvedBy: moderator,
            moderatorAction: logEntry.type,
            moderatorActionDescription: action,
            resolutionContext: actionContext,
            responseTime,
            isLateResponse
        }, 90 * 24 * 60 * 60); // Keep for 90 days

        // Send resolution notification
        const lateResponseSuffix = isLateResponse ? ' ⚠️ (Late Response)' : '';
        const title = actionContext === 'user'
            ? `✅ ${this.getDetectionTypeLabel(detectionType)} - User Action Taken${lateResponseSuffix}`
            : `✅ ${this.getDetectionTypeLabel(detectionType)} - Potentially Resolved${lateResponseSuffix}`;

        const detectionTimeUnix = Math.floor(detectionTime / 1000);
        const actionTimeUnix = Math.floor(actionTime / 1000);

        const description = actionContext === 'user'
            ? `**User:** @${detection.username}\n**Moderator:** @${moderator}\n**Action:** ${action} (user-level)\n**Original Detection:** <t:${detectionTimeUnix}:R>\n**Response Time:** ${responseTimeFormatted}${isLateResponse ? ' ⚠️' : ''}`
            : `**User:** @${detection.username}\n**Moderator:** @${moderator}\n**Action:** ${action}\n**Original Detection:** <t:${detectionTimeUnix}:R>\n**Response Time:** ${responseTimeFormatted}${isLateResponse ? ' ⚠️' : ''}`;

        await this.notifications.notify({
            type: 'spam_detected', // Reusing existing type
            severity: 'low',
            title,
            description,
            metadata: {
                'Detection Type': this.getDetectionTypeLabel(detectionType),
                'Note ID': detection.noteId,
                'User': `@${detection.username}`,
                'Moderator Action': action,
                'Action Context': actionContext === 'user' ? 'User-level action' : actionContext === 'file' ? 'File-level action' : 'Note-level action',
                'Moderator': `@${moderator}`,
                'Action Time': `<t:${actionTimeUnix}:F>`,
                'Original Detection': `<t:${detectionTimeUnix}:F>`,
                'Response Time': `${responseTimeFormatted}${isLateResponse ? ' ⚠️ Late' : ''}`,
                'Note URL': noteUrl,
                'User Profile': userUrl,
                'Original Reason': this.getOriginalReason(detectionType, detection)
            },
            timestamp: new Date()
        });
    }

    private getActionDescription(type: string): string {
        const actionMap: Record<string, string> = {
            'deleteNote': 'Note deleted',
            'suspendUser': 'User suspended',
            'silenceUser': 'User silenced',
            'unsilenceUser': 'User unsilenced',
            'unsuspendUser': 'User unsuspended',
            'forceAdultsOnly': 'Marked as adults only',
            'deleteFile': 'File deleted',
            'resetPassword': 'Password reset',
            'deleteAccount': 'Account deleted',
            'updateNote': 'Note updated',
            'createGlobalAnnouncement': 'Global announcement',
            'createUserAnnouncement': 'User announcement',
            'updateUserAnnouncement': 'User announcement updated',
            'deleteUserAnnouncement': 'User announcement deleted'
        };

        return actionMap[type] || type;
    }

    private getDetectionTypeLabel(type: string): string {
        const labels: Record<string, string> = {
            'nsfw': '🔞 NSFW Content',
            'spam': '🚫 Spam',
            'phishing': '🎣 Phishing',
            'virus': '🦠 Malware/Virus'
        };

        return labels[type] || type.toUpperCase();
    }

    private formatResponseTime(milliseconds: number): string {
        const seconds = Math.floor(milliseconds / 1000);
        const minutes = Math.floor(seconds / 60);
        const hours = Math.floor(minutes / 60);
        const days = Math.floor(hours / 24);

        if (days > 0) return `${days}d ${hours % 24}h ${minutes % 60}m`;
        if (hours > 0) return `${hours}h ${minutes % 60}m`;
        if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
        return `${seconds}s`;
    }

    private formatDetectionTime(timestamp: number): string {
        const now = Date.now();
        const diff = now - timestamp;
        const relativeTime = this.formatResponseTime(diff);
        const absoluteTime = new Date(timestamp).toLocaleString();
        return `${absoluteTime} (${relativeTime} ago)`;
    }

    private getOriginalReason(type: string, detection: any): string {
        if (type === 'nsfw') {
            return detection.reasons?.join(', ') || `Confidence: ${detection.confidence}%`;
        } else if (type === 'spam') {
            return detection.indicators?.join(', ') || `Score: ${detection.score}`;
        } else if (type === 'phishing') {
            return detection.indicators?.join(', ') || `Risk Score: ${detection.score}`;
        } else if (type === 'virus') {
            return detection.threats?.join(', ') || 'Malware detected';
        }
        return 'N/A';
    }

    getStats() {
        return {
            resolved: this.resolvedCount,
            ignoredSelfActions: this.ignoredSelfActions,
            ignoredAutomodActions: this.ignoredAutomodActions,
            lateResponses: this.lateResponses
        };
    }
}
