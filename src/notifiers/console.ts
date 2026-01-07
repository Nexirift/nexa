import { Notifier, ModerationEvent } from './abstract';

export class ConsoleNotifier extends Notifier {
    async notify(event: ModerationEvent): Promise<void> {
        if (!this.enabled) return;

        const emoji = this.getSeverityEmoji(event.severity);
        console.log(`\n${emoji} [${event.type.toUpperCase()}] ${event.title}`);
        console.log(`   ${event.description}`);

        if (event.metadata) {
            console.log('   Metadata:', event.metadata);
        }
        console.log();
    }

    private getSeverityEmoji(severity: ModerationEvent['severity']): string {
        const emojis = {
            low: 'ℹ️',
            medium: '⚠️',
            high: '🚨',
            critical: '🔴',
        };
        return emojis[severity];
    }
}
