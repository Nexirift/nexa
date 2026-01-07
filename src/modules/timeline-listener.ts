import * as Misskey from '@nexirift/pulsar-js';
import { cache } from './cache';
import { NotificationManager } from '../notifiers';
import EventEmitter from 'events';

export interface TimelineListenerOptions {
    instanceUrl: string;
    token: string;
    channels?: ('global' | 'local' | 'home')[];
}

export class TimelineListener extends EventEmitter {
    private stream: Misskey.Stream;
    private channels: Map<string, any> = new Map();
    private isRunning = false;
    private notifications: NotificationManager;

    constructor(
        private options: TimelineListenerOptions,
        notifications: NotificationManager
    ) {
        super();
        this.stream = new Misskey.Stream(options.instanceUrl, {
            token: options.token
        });
        this.notifications = notifications;
    }

    /**
     * Start listening to timelines
     */
    async start(): Promise<void> {
        if (this.isRunning) {
            console.warn('Timeline listener is already running');
            return;
        }

        const channelsToListen = this.options.channels || ['global'];

        for (const channelType of channelsToListen) {
            this.subscribeToChannel(channelType);
        }

        this.isRunning = true;
        console.log(`Timeline listener started for channels: ${channelsToListen.join(', ')}`);
    }

    /**
     * Subscribe to a specific timeline channel
     */
    private subscribeToChannel(channelType: 'global' | 'local' | 'home'): void {
        const channelName = `${channelType}Timeline`;
        const channel = this.stream.useChannel(channelName as any);

        channel.on('note', async (note: Misskey.entities.Note) => {
            await this.handleNote(note, channelType);
        });

        this.channels.set(channelType, channel);
        console.log(`Subscribed to ${channelType} timeline`);
    }

    /**
     * Handle incoming notes
     */
    private async handleNote(note: Misskey.entities.Note, channel: string): Promise<void> {
        try {
            // Cache the note
            cache.setNote(note.id, { ...note, cachedAt: Date.now() });

            // Emit event for other modules to handle
            this.emit('note', note, channel);
        } catch (error) {
            console.error('Error handling note:', error);
            this.emit('error', error);
        }
    }

    /**
     * Stop listening to timelines
     */
    async stop(): Promise<void> {
        if (!this.isRunning) {
            console.warn('Timeline listener is not running');
            return;
        }

        // Disconnect channels
        for (const [channelType, channel] of this.channels.entries()) {
            channel.dispose();
            console.log(`Unsubscribed from ${channelType} timeline`);
        }

        this.channels.clear();
        this.isRunning = false;
        console.log('Timeline listener stopped');
    }

    /**
     * Check if listener is running
     */
    isActive(): boolean {
        return this.isRunning;
    }
}
