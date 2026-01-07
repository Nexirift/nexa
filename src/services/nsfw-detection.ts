import * as Misskey from '@nexirift/pulsar-js';
import { TimelineListener } from '../modules/timeline-listener';
import { cache } from '../modules/cache';
import { NotificationManager } from '../notifiers';
import * as nsfwjs from 'nsfwjs';
import * as tf from '@tensorflow/tfjs-node';
import * as https from 'https';
import * as http from 'http';
import sharp from 'sharp';

export interface NSFWDetectionOptions {
    threshold?: number; // 0-1, higher = stricter
    autoFlag?: boolean;
    scanImages?: boolean;
    scanText?: boolean;
    instanceUrl?: string;
}

/**
 * NSFW Detection Service
 * Scans posts for NSFW content in images and text
 */
export class NSFWDetectionService {
    private detectedCount = 0;
    private scannedCount = 0;
    private model: nsfwjs.NSFWJS | null = null;
    private modelLoading: Promise<void> | null = null;

    constructor(
        private timelineListener: TimelineListener,
        private notifications: NotificationManager,
        private options: NSFWDetectionOptions = {}
    ) {
        this.options = {
            threshold: 0.7,
            autoFlag: true,
            scanImages: true,
            scanText: true,
            ...options
        };
        this.setupListeners();
        if (this.options.scanImages) {
            this.modelLoading = this.loadModel();
        }
    }

    private async loadModel(): Promise<void> {
        try {
            console.log('Loading NSFWJS model...');
            this.model = await nsfwjs.load();
            console.log('NSFWJS model loaded successfully');
        } catch (error) {
            console.error('Failed to load NSFWJS model:', error);
            this.model = null;
        }
    }

    private setupListeners(): void {
        this.timelineListener.on('note', (note: Misskey.entities.Note, channel: string) => {
            this.scanNote(note, channel);
        });

        console.log('NSFW Detection Service initialized');
    }

    private async scanNote(note: Misskey.entities.Note, channel: string): Promise<void> {
        this.scannedCount++;

        // Skip if note is already marked as sensitive
        // if (note.cw || note.files?.some(f => f.isSensitive)) {
        //     return;
        // }

        let isNSFW = false;
        let confidence = 0;
        const reasons: string[] = [];

        // Scan images if enabled
        if (this.options.scanImages && note.files && note.files.length > 0) {
            const imageResult = await this.scanImages(note.files);
            if (imageResult.isNSFW) {
                isNSFW = true;
                confidence = Math.max(confidence, imageResult.confidence);
                reasons.push(`NSFW image detected (${Math.round(imageResult.confidence * 100)}%)`);
            }
        }

        // Scan text if enabled
        if (this.options.scanText && note.text) {
            const textResult = this.scanText(note.text);
            if (textResult.isNSFW) {
                isNSFW = true;
                confidence = Math.max(confidence, textResult.confidence);
                reasons.push(`NSFW text detected (${Math.round(textResult.confidence * 100)}%)`);
            }
        }

        if (isNSFW && confidence >= this.options.threshold!) {
            this.detectedCount++;
            await this.handleNSFWContent(note, channel, confidence, reasons);
        }
    }

    private async scanImages(files: Misskey.entities.DriveFile[]): Promise<{ isNSFW: boolean; confidence: number }> {
        console.log(`   🔍 [NSFW] Scanning ${files.length} image(s)...`);

        // Wait for model to load if still loading
        if (this.modelLoading) {
            await this.modelLoading;
        }

        if (!this.model) {
            console.warn('   ⚠️ NSFWJS model not loaded, skipping image scan');
            return { isNSFW: false, confidence: 0 };
        }

        let maxNSFWScore = 0;
        const imageResults: Array<{ url: string; predictions: any }> = [];

        for (const file of files) {
            // Only scan images
            if (!file.type?.startsWith('image/')) continue;

            try {
                // Stream and convert image to JPG
                const imageBuffer = await this.streamAndConvertImage(file.url);

                // Convert to tensor
                const imageTensor = tf.node.decodeImage(imageBuffer, 3);

                // Get predictions
                const predictions = await this.model.classify(imageTensor as any);

                // Clean up tensor
                imageTensor.dispose();

                // Calculate NSFW score
                // nsfwjs returns: Drawing, Hentai, Neutral, Porn, Sexy
                const nsfwScore = predictions.reduce((score, pred) => {
                    if (['Hentai', 'Porn'].includes(pred.className)) {
                        return score + pred.probability;
                    }
                    if (pred.className === 'Sexy') {
                        return score + (pred.probability * 0.5); // Weight sexy lower
                    }
                    return score;
                }, 0);

                maxNSFWScore = Math.max(maxNSFWScore, nsfwScore);
                imageResults.push({ url: file.url, predictions });

                console.log(`   📊 Image: ${file.name} - NSFW score: ${(nsfwScore * 100).toFixed(1)}%`);
            } catch (error) {
                console.error(`   ❌ Failed to scan image ${file.name}:`, error);
            }
        }

        return {
            isNSFW: maxNSFWScore > 0.6, // Threshold for NSFW classification
            confidence: maxNSFWScore
        };
    }

    private streamAndConvertImage(url: string): Promise<Buffer> {
        return new Promise((resolve, reject) => {
            const client = url.startsWith('https') ? https : http;

            client.get(url, (response) => {
                if (response.statusCode !== 200) {
                    reject(new Error(`Failed to download image: ${response.statusCode}`));
                    return;
                }

                // Create sharp transformer to convert to JPG
                const transformer = sharp()
                    .jpeg({ quality: 90 }); // Convert to JPG with 90% quality

                // Pipe the response stream through sharp
                const chunks: Buffer[] = [];
                response.pipe(transformer)
                    .on('data', (chunk) => chunks.push(chunk))
                    .on('end', () => resolve(Buffer.concat(chunks)))
                    .on('error', reject);
            }).on('error', reject);
        });
    }

    private getRecommendedActions(note: Misskey.entities.Note, confidence: number, reasons: string[]): string {
        // Return natural language recommendation
        return "Mark the image as sensitive if it is not full on NSFW, otherwise, warn the user. If it is repeated, forcefully mark the account as adults only.";
    }

    private scanText(text: string): { isNSFW: boolean; confidence: number } {
        const nsfwKeywords = [
            /\b(?:porn|pornography|xxx|nsfw|adult content|explicit)\b/i,
            /\b(?:nude|naked|nudity|strip|stripper)\b/i,
            /\b(?:sex|sexual|erotic|hentai|doujin)\b/i,
            /\b(?:onlyfans|patreon)\b.*\b(?:nude|lewd|nsfw)\b/i,
            /\b(?:cam girl|webcam|live show)\b/i,
            /\b(?:18\+|adult only|mature content)\b/i,
        ];

        let matches = 0;
        let totalWeight = 0;
        const weights = [2, 2, 1.5, 2, 1.5, 1]; // Different weights for different patterns

        for (let i = 0; i < nsfwKeywords.length; i++) {
            if (nsfwKeywords[i].test(text)) {
                matches += weights[i];
            }
            totalWeight += weights[i];
        }

        const confidence = Math.min(matches / totalWeight, 1);

        return {
            isNSFW: matches >= 1.5, // Require at least one strong match or multiple weak
            confidence
        };
    }

    private async handleNSFWContent(
        note: Misskey.entities.Note,
        channel: string,
        confidence: number,
        reasons: string[]
    ): Promise<void> {
        const recommendedAction = this.getRecommendedActions(note, confidence, reasons);

        // Generate URLs
        const noteUrl = this.options.instanceUrl ? `${this.options.instanceUrl}/notes/${note.id}` : undefined;
        const userUrl = this.options.instanceUrl ? `${this.options.instanceUrl}/@${note.user.username}` : undefined;

        console.log(`\n🔞 [NSFW] Detected in note ${note.id}`);
        console.log(`   Channel: ${channel}`);
        console.log(`   User: @${note.user.username}`);
        console.log(`   Confidence: ${Math.round(confidence * 100)}%`);
        console.log(`   Reasons: ${reasons.join(', ')}`);
        if (noteUrl) console.log(`   Note URL: ${noteUrl}`);
        if (userUrl) console.log(`   User URL: ${userUrl}`);
        console.log(`   Recommended Action: ${recommendedAction}`);

        // Flag in cache
        if (this.options.autoFlag) {
            cache.set(`nsfw:${note.id}`, {
                noteId: note.id,
                userId: note.user.id,
                username: note.user.username,
                confidence,
                reasons,
                recommendedAction,
                noteUrl,
                userUrl,
                detectedAt: Date.now(),
                channel,
                resolved: false
            }, 30 * 24 * 60 * 60); // 30 days

            // Track user detections for moderator log correlation
            cache.addUserDetection('nsfw', note.user.id, note.id, 30 * 24 * 60 * 60);
        }

        // Send notification
        await this.notifications.notify({
            type: 'nsfw_detected',
            severity: confidence > 0.9 ? 'high' : confidence > 0.7 ? 'medium' : 'low',
            title: '🔞 NSFW Content Detected',
            description: `**User:** @${note.user.username}\n**Confidence:** ${Math.round(confidence * 100)}%\n**Channel:** ${channel}`,
            metadata: {
                'Note ID': note.id,
                'User': `@${note.user.username}`,
                'Confidence': `${Math.round(confidence * 100)}%`,
                'Reasons': reasons.join(', '),
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
