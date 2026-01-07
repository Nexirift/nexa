import { Notifier, ModerationEvent } from './abstract';

export class NotificationManager {
    private notifiers: Notifier[] = [];

    addNotifier(notifier: Notifier): void {
        this.notifiers.push(notifier);
    }

    async notify(event: ModerationEvent): Promise<void> {
        await Promise.allSettled(
            this.notifiers.map(notifier => notifier.notify(event))
        );
    }
}

export { Notifier, type ModerationEvent } from './abstract';
export { DiscordNotifier } from './discord';
export { ConsoleNotifier } from './console';
