import NodeCache from 'node-cache';
import { create as createFlatCache, type FlatCache } from 'flat-cache';
import * as Misskey from '@nexirift/pulsar-js';
import path from 'path';

interface CacheOptions {
    stdTTL?: number;
    checkperiod?: number;
    persistPath?: string;
    persistInterval?: number;
}

interface CacheStats {
    users: number;
    notes: number;
    hits: number;
    misses: number;
    keys: number;
}

export interface Note extends Misskey.entities.Note {
    cachedAt: number;
}

class PersistentCache {
    private memoryCache: NodeCache;
    private diskCache: FlatCache;
    private persistInterval: NodeJS.Timeout | null = null;
    private stats = { hits: 0, misses: 0 };

    private readonly PERSIST_INTERVAL: number;
    private readonly CLEANUP_INTERVAL = 60 * 60 * 1000; // 1 hour
    private readonly DEFAULT_TTL = 24 * 60 * 60; // 24 hours in seconds

    constructor(options: CacheOptions = {}) {
        const {
            stdTTL = this.DEFAULT_TTL,
            checkperiod = 600, // Check expired keys every 10 minutes
            persistPath = './data',
            persistInterval = 30000 // Persist every 30 seconds
        } = options;

        this.PERSIST_INTERVAL = persistInterval;

        // Initialize in-memory cache with TTL support
        this.memoryCache = new NodeCache({
            stdTTL,
            checkperiod,
            useClones: false,
            deleteOnExpire: true
        });

        // Initialize disk cache
        this.diskCache = createFlatCache({
            cacheId: 'nexa-cache',
            cacheDir: path.resolve(persistPath),
            persistInterval: 0 // Manual control
        });

        // Set up event listeners
        this.setupEventListeners();
    }

    private setupEventListeners(): void {
        // Track cache events
        this.memoryCache.on('expired', (key: string) => {
            console.log(`Cache key expired: ${key}`);
            this.diskCache.cache.delete(key);
        });

        this.memoryCache.on('del', (key: string) => {
            this.diskCache.cache.delete(key);
        });

        this.memoryCache.on('flush', () => {
            this.diskCache.cache.clear();
        });
    }

    /**
     * Initialize cache and restore from disk
     */
    async init(): Promise<void> {
        try {
            // Load from disk
            this.diskCache.load();

            // Restore all keys from disk into memory
            const allData = this.diskCache.all();
            let restored = 0;

            for (const [key, value] of Object.entries(allData)) {
                if (value !== undefined) {
                    // Restore to memory cache (will handle TTL)
                    this.memoryCache.set(key, value);
                    restored++;
                }
            }

            console.log(`Cache initialized: ${restored} keys restored from disk`);

            // Start auto-persist
            this.startAutoPersist();

            // Start periodic cleanup
            this.startPeriodicCleanup();

            return Promise.resolve();
        } catch (error) {
            console.error('Failed to initialize cache:', error);
            throw error;
        }
    }

    private startAutoPersist(): void {
        this.persistInterval = setInterval(() => {
            this.persist();
        }, this.PERSIST_INTERVAL);
    }

    private startPeriodicCleanup(): void {
        setInterval(() => {
            const stats = this.cleanup();
            if (stats.removed > 0) {
                console.log(`Periodic cleanup: ${stats.removed} keys removed`);
            }
        }, this.CLEANUP_INTERVAL);
    }

    /**
     * Persist memory cache to disk
     */
    private persist(): void {
        try {
            const keys = this.memoryCache.keys();

            // Sync memory to disk
            for (const key of keys) {
                const value = this.memoryCache.get(key);
                if (value !== undefined) {
                    this.diskCache.setKey(key, value);
                }
            }

            this.diskCache.save();
        } catch (error) {
            console.error('Failed to persist cache:', error);
        }
    }

    // User operations
    setUser<T = any>(id: string, data: T, ttl?: number): boolean {
        const key = `user:${id}`;
        const success = this.memoryCache.set(key, data, ttl || this.DEFAULT_TTL);
        if (success) {
            this.diskCache.setKey(key, data);
        }
        return success;
    }

    getUser<T = any>(id: string): T | undefined {
        const key = `user:${id}`;
        const value = this.memoryCache.get<T>(key);

        if (value !== undefined) {
            this.stats.hits++;
        } else {
            this.stats.misses++;
        }

        return value;
    }

    deleteUser(id: string): boolean {
        const key = `user:${id}`;
        const deleted = this.memoryCache.del(key) > 0;
        if (deleted) {
            this.diskCache.cache.delete(key);
        }
        return deleted;
    }

    hasUser(id: string): boolean {
        return this.memoryCache.has(`user:${id}`);
    }

    getAllUsers<T = any>(): Record<string, T> {
        const users: Record<string, T> = {};
        const keys = this.memoryCache.keys().filter(k => k.startsWith('user:'));

        for (const key of keys) {
            const id = key.replace('user:', '');
            const value = this.memoryCache.get<T>(key);
            if (value !== undefined) {
                users[id] = value;
            }
        }

        return users;
    }

    // Note operations
    setNote(id: string, data: Note, ttl?: number): boolean {
        const key = `note:${id}`;
        const success = this.memoryCache.set(key, data, ttl || this.DEFAULT_TTL);
        if (success) {
            this.diskCache.setKey(key, data);
        }
        return success;
    }

    getNote(id: string): Note | undefined {
        const key = `note:${id}`;
        const value = this.memoryCache.get<Note>(key);

        if (value !== undefined) {
            this.stats.hits++;
        } else {
            this.stats.misses++;
        }

        return value;
    }

    deleteNote(id: string): boolean {
        const key = `note:${id}`;
        const deleted = this.memoryCache.del(key) > 0;
        if (deleted) {
            this.diskCache.cache.delete(key);
        }
        return deleted;
    }

    hasNote(id: string): boolean {
        return this.memoryCache.has(`note:${id}`);
    }

    getAllNotes(): Record<string, Note> {
        const notes: Record<string, Note> = {};
        const keys = this.memoryCache.keys().filter(k => k.startsWith('note:'));

        for (const key of keys) {
            const id = key.replace('note:', '');
            const value = this.memoryCache.get<Note>(key);
            if (value !== undefined) {
                notes[id] = value;
            }
        }

        return notes;
    }

    // Generic operations
    set<T = any>(key: string, value: T, ttl?: number): boolean {
        const success = this.memoryCache.set(key, value, ttl || this.DEFAULT_TTL);
        if (success) {
            this.diskCache.setKey(key, value);
        }
        return success;
    }

    get<T = any>(key: string): T | undefined {
        const value = this.memoryCache.get<T>(key);

        if (value !== undefined) {
            this.stats.hits++;
        } else {
            this.stats.misses++;
        }

        return value;
    }

    delete(key: string): boolean {
        const deleted = this.memoryCache.del(key) > 0;
        if (deleted) {
            this.diskCache.cache.delete(key);
        }
        return deleted;
    }

    has(key: string): boolean {
        return this.memoryCache.has(key);
    }

    /**
     * Get multiple values at once
     */
    mget<T = any>(keys: string[]): Record<string, T> {
        const result: Record<string, T> = {};

        for (const key of keys) {
            const value = this.memoryCache.get<T>(key);
            if (value !== undefined) {
                result[key] = value;
                this.stats.hits++;
            } else {
                this.stats.misses++;
            }
        }

        return result;
    }

    /**
     * Update TTL for a key
     */
    ttl(key: string, seconds: number): boolean {
        return this.memoryCache.ttl(key, seconds);
    }

    /**
     * Get remaining TTL for a key
     */
    getTtl(key: string): number | undefined {
        return this.memoryCache.getTtl(key);
    }

    /**
     * Store a file-to-note mapping for virus detection lookups
     */
    setFileDetection(fileId: string, noteId: string, ttl?: number): boolean {
        const key = `virus:file:${fileId}`;
        return this.set(key, noteId, ttl);
    }

    /**
     * Get note ID associated with a file detection
     */
    getFileDetection(fileId: string): string | undefined {
        const key = `virus:file:${fileId}`;
        return this.get<string>(key);
    }

    /**
     * Store user detection mapping (for quick user-based lookups)
     */
    addUserDetection(type: string, userId: string, noteId: string, ttl?: number): boolean {
        const key = `${type}:user:${userId}:notes`;
        const existing = this.get<string[]>(key) || [];
        if (!existing.includes(noteId)) {
            existing.push(noteId);
        }
        return this.set(key, existing, ttl);
    }

    /**
     * Clean up expired entries and optionally by age
     */
    cleanup(maxAge?: number): { removed: number } {
        let removed = 0;

        if (maxAge) {
            const now = Date.now();
            const keys = this.memoryCache.keys();

            for (const key of keys) {
                const ttl = this.memoryCache.getTtl(key);
                if (ttl && (now - ttl > maxAge)) {
                    this.memoryCache.del(key);
                    this.diskCache.cache.delete(key);
                    removed++;
                }
            }
        } else {
            // node-cache automatically removes expired keys
            // Just persist current state
            this.persist();
        }

        return { removed };
    }

    /**
     * Clear all cache
     */
    clear(): void {
        this.memoryCache.flushAll();
        this.diskCache.cache.clear();
        this.diskCache.save();
    }

    /**
     * Get cache statistics
     */
    getStats(): CacheStats {
        const keys = this.memoryCache.keys();
        const userKeys = keys.filter(k => k.startsWith('user:')).length;
        const noteKeys = keys.filter(k => k.startsWith('note:')).length;

        return {
            users: userKeys,
            notes: noteKeys,
            keys: keys.length,
            hits: this.stats.hits,
            misses: this.stats.misses
        };
    }

    /**
     * Get hit rate
     */
    getHitRate(): number {
        const total = this.stats.hits + this.stats.misses;
        return total === 0 ? 0 : this.stats.hits / total;
    }

    /**
     * Reset statistics
     */
    resetStats(): void {
        this.stats = { hits: 0, misses: 0 };
    }

    /**
     * Shutdown cache gracefully
     */
    async shutdown(): Promise<void> {
        if (this.persistInterval) {
            clearInterval(this.persistInterval);
            this.persistInterval = null;
        }

        // Final persist
        this.persist();

        // Close memory cache
        this.memoryCache.close();

        console.log('Cache shutdown complete');
    }
}

// Global singleton instance
export const cache = new PersistentCache();

// Initialize on import
let isInitialized = false;
export const initCache = async () => {
    if (!isInitialized) {
        await cache.init();
        isInitialized = true;
    }
};

// Auto-initialize
initCache().catch(console.error);

// Graceful shutdown handlers
const shutdown = async () => {
    await cache.shutdown();
    process.exit(0);
};

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
process.on('beforeExit', () => {
    cache.shutdown().catch(console.error);
});

export default cache;
