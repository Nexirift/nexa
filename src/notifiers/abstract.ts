export interface ModerationEvent {
    type: 'nsfw_detected' | 'new_user' | 'user_changed' | 'spam_detected';
    severity: 'low' | 'medium' | 'high' | 'critical';
    title: string;
    description: string;
    metadata?: Record<string, any>;
    timestamp: Date;
}

export abstract class Notifier {
    protected enabled: boolean = true;

    abstract notify(event: ModerationEvent): Promise<void>;

    setEnabled(enabled: boolean): void {
        this.enabled = enabled;
    }

    isEnabled(): boolean {
        return this.enabled;
    }
}
