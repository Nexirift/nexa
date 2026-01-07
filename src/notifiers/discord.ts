import { EmbedBuilder, WebhookClient } from 'discord.js';
import { Notifier, ModerationEvent } from './abstract';

export class DiscordNotifier extends Notifier {
    private webhook: WebhookClient | null = null;

    constructor(webhookUrl: string) {
        super();
        if (webhookUrl) {
            try {
                this.webhook = new WebhookClient({ url: webhookUrl });
                console.log('✓ Discord notifications enabled');
            } catch (error) {
                console.error('Failed to initialize Discord webhook:', error);
                this.enabled = false;
            }
        } else {
            this.enabled = false;
        }
    }

    async notify(event: ModerationEvent): Promise<void> {
        if (!this.enabled || !this.webhook) return;

        try {
            const embed = new EmbedBuilder()
                .setTitle(event.title)
                .setDescription(event.description)
                .setColor(this.getSeverityColor(event.severity))
                .setTimestamp(event.timestamp);

            if (event.metadata) {
                // Quick links section (always first)
                const quickLinks = [];

                // Handle new user notifications
                if (event.type === 'new_user') {
                    if (event.metadata['Profile URL']) {
                        quickLinks.push(`[View Profile](${event.metadata['Profile URL']})`);
                    }
                    if (event.metadata['Admin Panel']) {
                        quickLinks.push(`[Admin Panel](${event.metadata['Admin Panel']})`);
                    }
                } else {
                    // Handle content moderation notifications
                    if (event.metadata['Note URL'] && event.metadata['Note URL'] !== 'N/A') {
                        quickLinks.push(`[View Note](${event.metadata['Note URL']})`);
                    }
                    if (event.metadata['User Profile'] && event.metadata['User Profile'] !== 'N/A') {
                        quickLinks.push(`[User Profile](${event.metadata['User Profile']})`);
                    }
                }

                if (quickLinks.length > 0) {
                    embed.addFields({
                        name: '🔗 Quick Links',
                        value: quickLinks.join(' • '),
                        inline: false
                    });
                }

                // Detection details section
                const detectionDetails = [];
                if (event.metadata['Confidence']) detectionDetails.push(`**Confidence:** ${event.metadata['Confidence']}`);
                if (event.metadata['Spam Score']) detectionDetails.push(`**Score:** ${event.metadata['Spam Score']}`);
                if (event.metadata['Risk Score']) detectionDetails.push(`**Risk Score:** ${event.metadata['Risk Score']}`);
                if (detectionDetails.length > 0) {
                    embed.addFields({
                        name: '📊 Detection Details',
                        value: detectionDetails.join('\n'),
                        inline: true
                    });
                }

                // Violation details - format as bullet lists for readability
                const violationDetails = [];

                if (event.metadata['Reasons']) {
                    const reasons = this.formatAsList(event.metadata['Reasons']);
                    violationDetails.push(`**Issues:**\n${reasons}`);
                }
                if (event.metadata['Violations']) {
                    const violations = this.formatAsList(event.metadata['Violations']);
                    violationDetails.push(`**Violations:**\n${violations}`);
                }
                if (event.metadata['Indicators']) {
                    const indicators = this.formatAsList(event.metadata['Indicators']);
                    violationDetails.push(`**Indicators:**\n${indicators}`);
                }
                if (event.metadata['Threats']) {
                    const threats = this.formatAsList(event.metadata['Threats']);
                    violationDetails.push(`**Threats:**\n${threats}`);
                }

                if (violationDetails.length > 0) {
                    embed.addFields({
                        name: '⚠️ Violation Details',
                        value: violationDetails.join('\n\n'),
                        inline: false
                    });
                }

                // Action/Status section
                if (event.metadata['Recommended Action']) {
                    embed.addFields({
                        name: '🎯 Recommended Action',
                        value: String(event.metadata['Recommended Action']),
                        inline: false
                    });
                }

                if (event.metadata['Auto-Delete Status']) {
                    embed.addFields({
                        name: '🤖 Automatic Action',
                        value: String(event.metadata['Auto-Delete Status']),
                        inline: false
                    });
                }

                // History section
                const historyInfo = [];
                if (event.metadata['Spam Count']) historyInfo.push(`**Spam:** ${event.metadata['Spam Count']}`);
                if (event.metadata['Violations']) historyInfo.push(`**Total:** ${event.metadata['Violations']}`);
                if (event.metadata['Violation Count']) historyInfo.push(`**Violations:** ${event.metadata['Violation Count']}`);
                if (event.metadata['Attempt Count']) historyInfo.push(`**Attempts:** ${event.metadata['Attempt Count']}`);
                if (historyInfo.length > 0) {
                    embed.addFields({
                        name: '📈 User History',
                        value: historyInfo.join('\n'),
                        inline: true
                    });
                }

                // Content preview (always last if present)
                if (event.metadata['Preview'] && event.metadata['Preview'] !== '(no text)') {
                    const preview = String(event.metadata['Preview']);
                    const truncated = preview.length > 200 ? preview.substring(0, 200) + '...' : preview;
                    embed.addFields({
                        name: '📝 Content Preview',
                        value: '```\n' + truncated + '\n```',
                        inline: false
                    });
                }

                // Technical details (collapsed at bottom)
                if (event.metadata['Note ID']) {
                    embed.setFooter({ text: `Note ID: ${event.metadata['Note ID']} • User: ${event.metadata['User'] || 'Unknown'}` });
                }
            }

            await this.webhook.send({ embeds: [embed] });
        } catch (error) {
            console.error('Failed to send Discord notification:', error);
        }
    }

    private formatAsList(value: any): string {
        if (typeof value !== 'string') {
            return String(value);
        }

        // Split by comma and format as bullet list
        const items = value.split(',').map(item => item.trim()).filter(item => item.length > 0);

        // Limit to first 10 items to avoid Discord embed limits
        const displayItems = items.slice(0, 10);
        const remaining = items.length - displayItems.length;

        let result = displayItems.map(item => `• ${item}`).join('\n');

        if (remaining > 0) {
            result += `\n• *...and ${remaining} more*`;
        }

        return result;
    }

    private getSeverityColor(severity: ModerationEvent['severity']): number {
        const colors = {
            low: 0x3498db,      // Blue
            medium: 0xf39c12,   // Orange
            high: 0xe74c3c,     // Red
            critical: 0x9b59b6, // Purple
        };
        return colors[severity];
    }

    async destroy(): Promise<void> {
        if (this.webhook) {
            this.webhook.destroy();
        }
    }
}
