import * as Misskey from '@nexirift/pulsar-js';
import { TimelineListener } from '../modules/timeline-listener';
import { cache } from '../modules/cache';
import { NotificationManager } from '../notifiers';

export interface SpamDetectionOptions {
    checkRepeatedContent?: boolean;
    checkUrls?: boolean;
    checkMentions?: boolean;
    rateLimitWindow?: number; // in milliseconds
    maxPostsPerWindow?: number;
    instanceUrl?: string;
}

/**
 * Spam Detection Service
 * Detects spam patterns in posts and user behavior
 */
export class SpamDetectionService {
    private detectedCount = 0;
    private scannedCount = 0;

    constructor(
        private timelineListener: TimelineListener,
        private notifications: NotificationManager,
        private options: SpamDetectionOptions = {}
    ) {
        this.options = {
            checkRepeatedContent: true,
            checkUrls: true,
            checkMentions: true,
            rateLimitWindow: 60 * 1000, // 1 minute
            maxPostsPerWindow: 5,
            ...options
        };
        this.setupListeners();
    }

    private setupListeners(): void {
        this.timelineListener.on('note', (note: Misskey.entities.Note, channel: string) => {
            this.scanNote(note, channel);
        });

        console.log('Spam Detection Service initialized');
    }

    private async scanNote(note: Misskey.entities.Note, channel: string): Promise<void> {
        this.scannedCount++;

        const spamIndicators: string[] = [];
        let spamScore = 0;

        // Check for URL spam
        if (this.options.checkUrls && note.text) {
            const urlSpam = this.checkUrlSpam(note.text);
            if (urlSpam.isSpam) {
                spamIndicators.push(urlSpam.reason);
                spamScore += urlSpam.score;
            }
        }

        // Check for repeated content
        if (this.options.checkRepeatedContent && note.text) {
            const repetitionSpam = this.checkRepetition(note.text);
            if (repetitionSpam.isSpam) {
                spamIndicators.push(repetitionSpam.reason);
                spamScore += repetitionSpam.score;
            }
        }

        // Check for mention spam
        if (this.options.checkMentions && note.text) {
            const mentionSpam = this.checkMentionSpam(note.text);
            if (mentionSpam.isSpam) {
                spamIndicators.push(mentionSpam.reason);
                spamScore += mentionSpam.score;
            }
        }

        // Check rate limiting
        const rateLimitSpam = await this.checkRateLimit(note.user.id);
        if (rateLimitSpam.isSpam) {
            spamIndicators.push(rateLimitSpam.reason);
            spamScore += rateLimitSpam.score;
        }

        // Check for spam keywords
        if (note.text) {
            const keywordSpam = this.checkSpamKeywords(note.text);
            if (keywordSpam.isSpam) {
                spamIndicators.push(keywordSpam.reason);
                spamScore += keywordSpam.score;
            }
        }

        // Check for low entropy (copy-paste spam)
        if (note.text && note.text.length > 50) {
            const entropyCheck = this.checkTextEntropy(note.text);
            if (entropyCheck.isSpam) {
                spamIndicators.push(entropyCheck.reason);
                spamScore += entropyCheck.score;
            }
        }

        // Check for duplicate content
        if (note.text) {
            const duplicateCheck = await this.checkDuplicateContent(note.user.id, note.text);
            if (duplicateCheck.isSpam) {
                spamIndicators.push(duplicateCheck.reason);
                spamScore += duplicateCheck.score;
            }
        }

        // Check for emoji spam
        if (note.text) {
            const emojiSpam = this.checkEmojiSpam(note.text);
            if (emojiSpam.isSpam) {
                spamIndicators.push(emojiSpam.reason);
                spamScore += emojiSpam.score;
            }
        }

        if (spamScore >= 2) { // Threshold: 2 or more indicators
            this.detectedCount++;
            await this.handleSpam(note, channel, spamIndicators, spamScore);
        }
    }

    private checkUrlSpam(text: string): { isSpam: boolean; reason: string; score: number } {
        const urlPattern = /https?:\/\/[^\s<>]+/gi;
        const urls = text.match(urlPattern) || [];

        // Too many URLs
        if (urls.length >= 3) {
            return { isSpam: true, reason: `Multiple URLs (${urls.length})`, score: 2 };
        }

        // URL-only post
        if (urls.length > 0 && text.replace(urlPattern, '').trim().length < 10) {
            return { isSpam: true, reason: 'URL-only post', score: 1 };
        }

        return { isSpam: false, reason: '', score: 0 };
    }

    private checkRepetition(text: string): { isSpam: boolean; reason: string; score: number } {
        // Check for repeated characters
        if (/(.)\1{10,}/.test(text)) {
            return { isSpam: true, reason: 'Repeated characters', score: 1 };
        }

        // Check for repeated words
        const words = text.toLowerCase().split(/\s+/);
        const wordCounts = new Map<string, number>();

        for (const word of words) {
            if (word.length < 3) continue;
            wordCounts.set(word, (wordCounts.get(word) || 0) + 1);
        }

        for (const [word, count] of wordCounts) {
            if (count >= 5) {
                return { isSpam: true, reason: `Repeated word: "${word}" (${count}x)`, score: 1 };
            }
        }

        return { isSpam: false, reason: '', score: 0 };
    }

    private checkMentionSpam(text: string): { isSpam: boolean; reason: string; score: number } {
        const mentions = text.match(/@[\w-]+/g) || [];

        if (mentions.length >= 5) {
            return { isSpam: true, reason: `Excessive mentions (${mentions.length})`, score: 2 };
        }

        return { isSpam: false, reason: '', score: 0 };
    }

    private async checkRateLimit(userId: string): Promise<{ isSpam: boolean; reason: string; score: number }> {
        const key = `ratelimit:${userId}`;
        const now = Date.now();
        const window = this.options.rateLimitWindow!;

        // Get recent posts
        const recentPosts = cache.get<number[]>(key) || [];

        // Filter to current window
        const postsInWindow = recentPosts.filter(timestamp => now - timestamp < window);

        // Add current post
        postsInWindow.push(now);

        // Update cache
        cache.set(key, postsInWindow, Math.ceil(window / 1000));

        if (postsInWindow.length > this.options.maxPostsPerWindow!) {
            return {
                isSpam: true,
                reason: `Rate limit exceeded (${postsInWindow.length} posts in ${window / 1000}s)`,
                score: 2
            };
        }

        return { isSpam: false, reason: '', score: 0 };
    }

    private checkSpamKeywords(text: string): { isSpam: boolean; reason: string; score: number } {
        const spamKeywords = [
            // Marketing/sales spam
            /\b(buy now|click here|limited time|act now|order now|shop now)\b/i,
            /\b(free money|make money|get rich|earn (cash|money)|passive income)\b/i,
            /\b(winner|you('ve)? won|claim (your )?prize|congratulations)\b.*\b(prize|reward|gift)\b/i,

            // Crypto/investment spam
            /\b(crypto|bitcoin|ethereum|nft|web3)\b.*\b(guaranteed|instant|easy|quick)\b/i,
            /\b(investment|trading|forex)\b.*\b(profit|return|roi)\b.*\b(guaranteed|100%)\b/i,
            /\b(pump|moon|lambo|wen|hodl)\b.*\b(100x|1000x|\d+x gains)\b/i,

            // Follow-for-follow spam
            /\b(follow back|f4f|followback|follow for follow|mutual|follow train)\b/i,
            /\b(like for like|l4l|sub(scribe)? for sub|s4s)\b/i,

            // Engagement bait
            /\b(check out|visit|go to)\b.*\b(my|our)\b.*\b(profile|page|website|link|bio)\b/i,
            /\b(dm me|message me|contact me)\b.*\b(for|about|regarding)\b/i,

            // Scam indicators
            /\b(work from home|make \$\d+|\$\d+ (per|a) (day|hour|week))\b/i,
            /\b(no experience needed|easy work|simple task)\b.*\b(\$|money|cash|earn)\b/i,
        ];

        let matchCount = 0;
        const matchedPatterns: string[] = [];

        for (const pattern of spamKeywords) {
            if (pattern.test(text)) {
                matchCount++;
                matchedPatterns.push(pattern.source.substring(0, 30));
            }
        }

        // Multiple spam keyword matches = higher score
        const score = matchCount >= 2 ? 2 : matchCount >= 1 ? 1 : 0;

        return {
            isSpam: matchCount > 0,
            reason: matchCount > 0 ? `Spam keywords (${matchCount} pattern${matchCount > 1 ? 's' : ''})` : '',
            score
        };
    }

    private checkTextEntropy(text: string): { isSpam: boolean; reason: string; score: number } {
        // Calculate Shannon entropy to detect copy-paste spam
        const charCounts = new Map<string, number>();

        for (const char of text.toLowerCase()) {
            if (char.match(/[a-z0-9]/)) {
                charCounts.set(char, (charCounts.get(char) || 0) + 1);
            }
        }

        const length = Array.from(charCounts.values()).reduce((a, b) => a + b, 0);
        let entropy = 0;

        for (const count of charCounts.values()) {
            const probability = count / length;
            entropy -= probability * Math.log2(probability);
        }

        // Low entropy (< 3.0) suggests repetitive/templated content
        if (entropy < 3.0) {
            return {
                isSpam: true,
                reason: `Low text entropy (${entropy.toFixed(2)})`,
                score: 1
            };
        }

        return { isSpam: false, reason: '', score: 0 };
    }

    private async checkDuplicateContent(userId: string, text: string): Promise<{ isSpam: boolean; reason: string; score: number }> {
        const contentHash = this.simpleHash(text);
        const key = `content:${userId}:${contentHash}`;

        // Check if we've seen this exact content recently
        const lastSeen = cache.get<number>(key);
        const now = Date.now();

        if (lastSeen && now - lastSeen < 60 * 60 * 1000) { // Within 1 hour
            return {
                isSpam: true,
                reason: 'Duplicate content posted recently',
                score: 2
            };
        }

        // Store content hash
        cache.set(key, now, 60 * 60); // 1 hour

        return { isSpam: false, reason: '', score: 0 };
    }

    private simpleHash(text: string): string {
        // Simple hash for duplicate detection
        let hash = 0;
        for (let i = 0; i < text.length; i++) {
            const char = text.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32-bit integer
        }
        return hash.toString(36);
    }

    private checkEmojiSpam(text: string): { isSpam: boolean; reason: string; score: number } {
        // Count emojis (rough approximation)
        const emojiPattern = /[\u{1F300}-\u{1F9FF}\u{2600}-\u{26FF}\u{2700}-\u{27BF}]/gu;
        const emojis = text.match(emojiPattern) || [];
        const emojiCount = emojis.length;

        // Count total characters
        const totalChars = text.length;

        // If more than 30% emojis, likely spam
        if (totalChars > 0 && (emojiCount / totalChars) > 0.3) {
            return {
                isSpam: true,
                reason: `Excessive emojis (${emojiCount}/${totalChars})`,
                score: 1
            };
        }

        return { isSpam: false, reason: '', score: 0 };
    }

    private getRecommendedActions(note: Misskey.entities.Note, score: number, indicators: string[]): string {
        return "Delete the content. If constantly repeated, suspend the user.";
    }

    private async handleSpam(
        note: Misskey.entities.Note,
        channel: string,
        indicators: string[],
        score: number
    ): Promise<void> {
        const recommendedAction = this.getRecommendedActions(note, score, indicators);

        // Generate URLs
        const noteUrl = this.options.instanceUrl ? `${this.options.instanceUrl}/notes/${note.id}` : undefined;
        const userUrl = this.options.instanceUrl ? `${this.options.instanceUrl}/@${note.user.username}` : undefined;

        console.log(`\n🚫 [SPAM] Detected in note ${note.id}`);
        console.log(`   Channel: ${channel}`);
        console.log(`   User: @${note.user.username}`);
        console.log(`   Score: ${score}`);
        console.log(`   Indicators: ${indicators.join(', ')}`);
        if (noteUrl) console.log(`   Note URL: ${noteUrl}`);
        if (userUrl) console.log(`   User URL: ${userUrl}`);
        console.log(`   Recommended Action: ${recommendedAction}`);

        // Track user spam history
        const userSpamKey = `spam:user:${note.user.id}`;
        const spamHistory = cache.get<number>(userSpamKey) || 0;
        cache.set(userSpamKey, spamHistory + 1, 30 * 24 * 60 * 60); // 30 days

        // Flag in cache
        cache.set(`spam:${note.id}`, {
            noteId: note.id,
            userId: note.user.id,
            username: note.user.username,
            indicators,
            score,
            recommendedAction,
            noteUrl,
            userUrl,
            spamCount: spamHistory + 1,
            detectedAt: Date.now(),
            channel,
            resolved: false
        }, 7 * 24 * 60 * 60); // 7 days

        // Track user detections for moderator log correlation
        cache.addUserDetection('spam', note.user.id, note.id, 7 * 24 * 60 * 60);

        // Send notification
        const severity = score >= 4 ? 'critical' : score >= 3 ? 'high' : score >= 2 ? 'medium' : 'low';
        await this.notifications.notify({
            type: 'spam_detected',
            severity,
            title: '🚫 Spam Detected',
            description: `**User:** @${note.user.username}\n**Spam Score:** ${score}\n**Channel:** ${channel}${spamHistory > 0 ? `\n**Repeat Offender:** ${spamHistory + 1} violations` : ''}`,
            metadata: {
                'Note ID': note.id,
                'User': `@${note.user.username}`,
                'Spam Score': `${score}/5`,
                'Violations': indicators.join(', '),
                'Spam Count': `${spamHistory + 1} total`,
                'Recommended Action': recommendedAction,
                'Note URL': noteUrl || 'N/A',
                'User Profile': userUrl || 'N/A',
                'Preview': note.text?.substring(0, 100) || '(no text)'
            },
            timestamp: new Date()
        });
    }

    getStats() {
        return {
            scanned: this.scannedCount,
            detected: this.detectedCount,
            detectionRate: this.scannedCount > 0 ? (this.detectedCount / this.scannedCount) : 0
        };
    }
}
