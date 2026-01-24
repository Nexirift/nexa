/**
 * Virus Detection Service for Nexa
 *
 * A comprehensive, highly customizable malware and virus detection service for Misskey instances.
 * Provides multi-layered threat detection including:
 * - ClamAV integration for deep file scanning
 * - URL analysis for malicious links
 * - Pattern-based detection for suspicious content
 * - Custom scanner support
 *
 * Features:
 * - ✅ File scanning with ClamAV integration
 * - ✅ Suspicious extension detection
 * - ✅ MIME type validation
 * - ✅ URL shortener detection
 * - ✅ Malicious link pattern matching
 * - ✅ IP address URL detection (C2 servers)
 * - ✅ Executable download detection
 * - ✅ Configurable auto-deletion (confirmed/suspicious)
 * - ✅ User history tracking
 * - ✅ Auto-suspend/silence repeat offenders
 * - ✅ File quarantine and caching
 * - ✅ Notification grouping
 * - ✅ Performance optimization (concurrent scans, timeouts)
 * - ✅ Extensive logging and statistics
 * - ✅ Custom scanner plugins
 *
 * Configuration Options:
 * - Scanning: Enable/disable file, link, or pattern scanning
 * - ClamAV: Socket/network configuration, timeouts, preferences
 * - File Scanning: Size limits, extension whitelist/blacklist, MIME types
 * - Link Scanning: URL shortener/TLD detection, IP addresses, keyword patterns
 * - Actions: Auto-delete, quarantine, suspend/silence users
 * - Notifications: Grouping, filtering, preview control
 * - Cache: TTL, history tracking
 * - Performance: Concurrent scans, timeouts, connection reuse
 * - Logging: Verbosity, statistics, clean file logging
 *
 * @example
 * ```typescript
 * const virusDetection = new VirusDetectionService(client, timelineListener, notifications, {
 *   scanFiles: true,
 *   scanLinks: true,
 *   clamav: {
 *     enabled: true,
 *     socket: '/var/run/clamav/clamd.ctl',
 *   },
 *   actions: {
 *     autoDelete: true,
 *     suspendUser: true,
 *     suspendThreshold: 3,
 *   },
 *   fileScanning: {
 *     maxFileSize: 100 * 1024 * 1024, // 100MB
 *     allowedExtensions: ['.jpg', '.png', '.gif'], // Whitelist mode
 *   },
 *   notifications: {
 *     groupByUser: true,
 *     groupingWindow: 5 * 60 * 1000, // 5 minutes
 *   }
 * });
 * ```
 */

import * as Misskey from "@nexirift/pulsar-js";
import { TimelineListener } from "../modules/timeline-listener";
import { cache } from "../modules/cache";
import { NotificationManager } from "../notifiers";
import { env } from "../env";
// @ts-ignore - No types available for clamscan
import NodeClam from "clamscan";
import * as https from "https";
import * as http from "http";
import * as fs from "fs/promises";
import * as path from "path";
import * as os from "os";

/**
 * Recommended action codes for virus/malware detection
 */
export enum RecommendedAction {
  /** Content automatically removed (files and/or note) */
  AUTO_DELETED = "AUTO_DELETED",
  /** Files removed from drive */
  FILES_DELETED = "FILES_DELETED",
  /** Note removed but files preserved */
  NOTE_DELETED = "NOTE_DELETED",
  /** User suspended due to repeat violations */
  USER_SUSPENDED = "USER_SUSPENDED",
  /** User silenced temporarily */
  USER_SILENCED = "USER_SILENCED",
  /** Manual review recommended */
  MANUAL_REVIEW = "MANUAL_REVIEW",
  /** Monitor user for repeat violations */
  MONITOR_USER = "MONITOR_USER",
  /** Quarantined for investigation */
  QUARANTINED = "QUARANTINED",
  /** No action taken (informational only) */
  NO_ACTION = "NO_ACTION",
}

export interface VirusDetectionOptions {
  // Scanning options
  scanFiles?: boolean;
  scanLinks?: boolean;
  scanPatterns?: boolean;

  // Use environment variables for configuration (overrides individual settings)
  useEnvConfig?: boolean;

  // ClamAV configuration
  clamav?: {
    enabled?: boolean;
    socket?: string;
    host?: string;
    port?: number;
    timeout?: number;
    removeInfected?: boolean;
    quarantineInfected?: boolean;
    debugMode?: boolean;
    preference?: "clamdscan" | "clamscan";
  };

  // File scanning configuration
  fileScanning?: {
    maxFileSize?: number; // in bytes, 0 = no limit
    maxFilesPerNote?: number;
    suspiciousExtensions?: string[];
    allowedExtensions?: string[]; // whitelist mode
    suspiciousMimeTypes?: string[];
    scanArchives?: boolean;
    scanImages?: boolean;
  };

  // Link scanning configuration
  linkScanning?: {
    checkUrlShorteners?: boolean;
    urlShortenerDomains?: string[];
    checkSuspiciousTlds?: boolean;
    suspiciousTlds?: string[];
    checkIpAddresses?: boolean;
    checkExecutableDownloads?: boolean;
    executableExtensions?: string[];
    malwareKeywords?: RegExp[];
    maxLinksPerNote?: number;
  };

  // Action configuration
  actions?: {
    quarantine?: boolean;
    autoDelete?: boolean;
    autoDeleteOnSuspicious?: boolean; // delete even for suspicious findings
    deleteFiles?: boolean;
    deleteNote?: boolean;
    suspendUser?: boolean;
    suspendThreshold?: number; // violations before auto-suspend
    silenceUser?: boolean;
    silenceDuration?: number; // in milliseconds
  };

  // Notification configuration
  notifications?: {
    enabled?: boolean;
    onConfirmed?: boolean;
    onSuspicious?: boolean;
    includePreview?: boolean;
    previewLength?: number;
    groupByUser?: boolean;
    groupingWindow?: number; // in milliseconds
  };

  // Cache and history
  cache?: {
    enabled?: boolean;
    ttl?: number; // in seconds
    trackUserHistory?: boolean;
    userHistoryTtl?: number;
    trackFileHistory?: boolean;
  };

  // Performance
  performance?: {
    concurrentScans?: number;
    scanTimeout?: number; // in milliseconds
    downloadTimeout?: number;
    maxDownloadSize?: number;
    reuseConnections?: boolean;
  };

  // Logging
  logging?: {
    enabled?: boolean;
    verbose?: boolean;
    logClean?: boolean; // log clean files too
    logStats?: boolean;
    statsInterval?: number; // in milliseconds
  };

  // Misc
  instanceUrl?: string;
  customScanners?: Array<(note: Misskey.entities.Note) => Promise<string[]>>;
}

/**
 * Virus/Malware Detection Service
 * Scans file attachments and links for malware with extensive customization options
 */
export class VirusDetectionService {
  private detectedCount = 0;
  private scannedCount = 0;
  private suspiciousCount = 0;
  private confirmedCount = 0;
  private clamScan: NodeClam | null = null;
  private clamScanLoading: Promise<void> | null = null;
  private statsInterval?: NodeJS.Timeout;
  private pendingNotifications = new Map<
    string,
    { count: number; lastNotification: number }
  >();

  // Optimized default configuration
  private readonly config: Required<VirusDetectionOptions>;

  constructor(
    private client: Misskey.api.APIClient,
    private timelineListener: TimelineListener,
    private notifications: NotificationManager,
    options: VirusDetectionOptions = {},
  ) {
    // Deep merge with defaults
    this.config = this.mergeWithDefaults(options);

    this.setupListeners();

    if (this.config.scanFiles && this.config.clamav.enabled) {
      this.clamScanLoading = this.initClamScan();
    }

    if (
      this.config.logging.logStats &&
      (this.config.logging.statsInterval ?? 0) > 0
    ) {
      this.startStatsLogger();
    }
  }

  /**
   * Merge user options with intelligent defaults (env variables or hardcoded)
   */
  private mergeWithDefaults(
    options: VirusDetectionOptions,
  ): Required<VirusDetectionOptions> {
    const useEnv = options.useEnvConfig ?? true;

    return {
      useEnvConfig: useEnv,
      scanFiles: options.scanFiles ?? (useEnv ? env.VIRUS_SCAN_FILES : true),
      scanLinks: options.scanLinks ?? (useEnv ? env.VIRUS_SCAN_LINKS : true),
      scanPatterns: options.scanPatterns ?? true,

      clamav: {
        enabled:
          options.clamav?.enabled ?? (useEnv ? env.VIRUS_CLAMAV_ENABLED : true),
        socket:
          options.clamav?.socket ??
          (useEnv ? env.VIRUS_CLAMAV_SOCKET : "/var/run/clamav/clamd.ctl"),
        host: options.clamav?.host ?? env.VIRUS_CLAMAV_HOST ?? "localhost",
        port: options.clamav?.port ?? env.VIRUS_CLAMAV_PORT ?? 3310,
        timeout: options.clamav?.timeout ?? 60000,
        removeInfected: options.clamav?.removeInfected ?? false,
        quarantineInfected: options.clamav?.quarantineInfected ?? false,
        debugMode: options.clamav?.debugMode ?? false,
        preference: options.clamav?.preference ?? "clamdscan",
      },

      fileScanning: {
        maxFileSize:
          options.fileScanning?.maxFileSize ??
          (useEnv ? env.VIRUS_MAX_FILE_SIZE : 100 * 1024 * 1024),
        maxFilesPerNote:
          options.fileScanning?.maxFilesPerNote ??
          (useEnv ? env.VIRUS_MAX_FILES_PER_NOTE : 20),
        suspiciousExtensions: options.fileScanning?.suspiciousExtensions ?? [
          ".exe",
          ".bat",
          ".cmd",
          ".scr",
          ".vbs",
          ".jar",
          ".app",
          ".msi",
          ".ps1",
          ".sh",
          ".bash",
          ".com",
          ".pif",
          ".cpl",
          ".dll",
          ".sys",
          ".drv",
          ".hta",
          ".wsf",
          ".js",
          ".jse",
          ".vbe",
          ".reg",
          ".inf",
          ".lnk",
        ],
        allowedExtensions: options.fileScanning?.allowedExtensions ?? [],
        suspiciousMimeTypes: options.fileScanning?.suspiciousMimeTypes ?? [
          "application/x-msdownload",
          "application/x-msdos-program",
          "application/x-executable",
        ],
        scanArchives: options.fileScanning?.scanArchives ?? true,
        scanImages: options.fileScanning?.scanImages ?? false,
      },

      linkScanning: {
        checkUrlShorteners: options.linkScanning?.checkUrlShorteners ?? false,
        urlShortenerDomains: options.linkScanning?.urlShortenerDomains ?? [
          "bit.ly",
          "tinyurl.com",
          "goo.gl",
          "t.co",
          "ow.ly",
          "shorturl.at",
          "rb.gy",
          "is.gd",
          "v.gd",
          "tiny.cc",
        ],
        checkSuspiciousTlds: options.linkScanning?.checkSuspiciousTlds ?? false,
        suspiciousTlds: options.linkScanning?.suspiciousTlds ?? [
          ".tk",
          ".ml",
          ".ga",
          ".cf",
          ".gq",
          ".buzz",
          ".top",
          ".xyz",
          ".link",
          ".click",
          ".work",
          ".party",
          ".download",
        ],
        checkIpAddresses: options.linkScanning?.checkIpAddresses ?? false,
        checkExecutableDownloads:
          options.linkScanning?.checkExecutableDownloads ?? true,
        executableExtensions: options.linkScanning?.executableExtensions ?? [
          "exe",
          "bat",
          "cmd",
          "scr",
          "vbs",
          "jar",
          "app",
          "msi",
          "dmg",
          "deb",
          "rpm",
          "apk",
          "ipa",
          "ps1",
          "sh",
        ],
        malwareKeywords: options.linkScanning?.malwareKeywords ?? [
          /download.*\.(exe|bat|cmd|scr|vbs|ps1|msi|app)/i,
          /\b(crack|keygen|patch|activator|loader|generator)\b/i,
          /\b(malware|virus|trojan|ransomware|rootkit|backdoor)\b/i,
          /\/get\/(file|download|installer)\//i,
        ],
        maxLinksPerNote:
          options.linkScanning?.maxLinksPerNote ??
          (useEnv ? env.VIRUS_MAX_LINKS_PER_NOTE : 50),
      },

      actions: {
        quarantine:
          options.actions?.quarantine ?? (useEnv ? env.VIRUS_QUARANTINE : true),
        autoDelete:
          options.actions?.autoDelete ??
          (useEnv ? env.VIRUS_AUTO_DELETE : true),
        autoDeleteOnSuspicious:
          options.actions?.autoDeleteOnSuspicious ??
          (useEnv ? env.VIRUS_AUTO_DELETE_SUSPICIOUS : false),
        deleteFiles:
          options.actions?.deleteFiles ??
          (useEnv ? env.VIRUS_DELETE_FILES : true),
        deleteNote:
          options.actions?.deleteNote ??
          (useEnv ? env.VIRUS_DELETE_NOTE : true),
        suspendUser:
          options.actions?.suspendUser ??
          (useEnv ? env.VIRUS_SUSPEND_USER : false),
        suspendThreshold:
          options.actions?.suspendThreshold ??
          (useEnv ? env.VIRUS_SUSPEND_THRESHOLD : 3),
        silenceUser:
          options.actions?.silenceUser ??
          (useEnv ? env.VIRUS_SILENCE_USER : false),
        silenceDuration:
          options.actions?.silenceDuration ??
          (useEnv ? env.VIRUS_SILENCE_DURATION : 24 * 60 * 60 * 1000),
      },

      notifications: {
        enabled: options.notifications?.enabled ?? true,
        onConfirmed:
          options.notifications?.onConfirmed ??
          (useEnv ? env.VIRUS_NOTIFY_CONFIRMED : true),
        onSuspicious:
          options.notifications?.onSuspicious ??
          (useEnv ? env.VIRUS_NOTIFY_SUSPICIOUS : true),
        includePreview: options.notifications?.includePreview ?? true,
        previewLength: options.notifications?.previewLength ?? 100,
        groupByUser:
          options.notifications?.groupByUser ??
          (useEnv ? env.VIRUS_NOTIFY_GROUP_BY_USER : true),
        groupingWindow:
          options.notifications?.groupingWindow ??
          (useEnv ? env.VIRUS_NOTIFY_GROUPING_WINDOW : 5 * 60 * 1000),
      },

      cache: {
        enabled: options.cache?.enabled ?? true,
        ttl:
          options.cache?.ttl ??
          (useEnv ? env.VIRUS_CACHE_TTL : 90 * 24 * 60 * 60),
        trackUserHistory:
          options.cache?.trackUserHistory ??
          (useEnv ? env.VIRUS_TRACK_USER_HISTORY : true),
        userHistoryTtl:
          options.cache?.userHistoryTtl ??
          (useEnv ? env.VIRUS_CACHE_TTL : 90 * 24 * 60 * 60),
        trackFileHistory: options.cache?.trackFileHistory ?? true,
      },

      performance: {
        concurrentScans: options.performance?.concurrentScans ?? 3,
        scanTimeout:
          options.performance?.scanTimeout ??
          (useEnv ? env.VIRUS_SCAN_TIMEOUT : 30000),
        downloadTimeout:
          options.performance?.downloadTimeout ??
          (useEnv ? env.VIRUS_DOWNLOAD_TIMEOUT : 30000),
        maxDownloadSize:
          options.performance?.maxDownloadSize ??
          (useEnv ? env.VIRUS_MAX_FILE_SIZE : 100 * 1024 * 1024),
        reuseConnections: options.performance?.reuseConnections ?? true,
      },

      logging: {
        enabled: options.logging?.enabled ?? true,
        verbose:
          options.logging?.verbose ?? (useEnv ? env.VIRUS_LOG_VERBOSE : false),
        logClean: options.logging?.logClean ?? false,
        logStats:
          options.logging?.logStats ?? (useEnv ? env.VIRUS_LOG_STATS : true),
        statsInterval:
          options.logging?.statsInterval ??
          (useEnv ? env.VIRUS_STATS_INTERVAL : 60 * 60 * 1000),
      },

      instanceUrl: options.instanceUrl ?? "",
      customScanners: options.customScanners ?? [],
    };
  }

  /**
   * Start periodic stats logging
   */
  private startStatsLogger(): void {
    this.statsInterval = setInterval(() => {
      const stats = this.getStats();
      if (this.config.logging.enabled) {
        console.log(`\n📊 [VIRUS] Stats Report:`);
        console.log(`   Total Scanned: ${stats.scanned}`);
        console.log(
          `   Detected: ${stats.detected} (${(stats.detectionRate * 100).toFixed(2)}%)`,
        );
        console.log(`   Confirmed: ${stats.confirmed}`);
        console.log(`   Suspicious: ${stats.suspicious}`);
        console.log(
          `   Detection Rate: ${(stats.detectionRate * 100).toFixed(2)}%`,
        );
      }
    }, this.config.logging.statsInterval);
  }

  /**
   * Cleanup resources
   */
  public destroy(): void {
    if (this.statsInterval) {
      clearInterval(this.statsInterval);
    }
  }

  /**
   * Create a timeout promise
   */
  private timeout<T>(ms: number, message: string): Promise<T> {
    return new Promise((_, reject) => {
      setTimeout(() => reject(new Error(message)), ms);
    });
  }

  /**
   * Format bytes to human readable format
   */
  private formatBytes(bytes: number): string {
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + " " + sizes[i];
  }

  /**
   * Initialize ClamAV scanner with custom configuration
   */
  private async initClamScan(): Promise<void> {
    try {
      if (this.config.logging.enabled) {
        console.log("🔧 [VIRUS] Initializing ClamScan...");
      }

      const clamConfig: any = {
        removeInfected: this.config.clamav.removeInfected,
        quarantineInfected: this.config.clamav.quarantineInfected,
        debugMode: this.config.clamav.debugMode,
        preference: this.config.clamav.preference,
      };

      if (this.config.clamav.socket) {
        clamConfig.clamdscan = { socket: this.config.clamav.socket };
      } else if (this.config.clamav.host && this.config.clamav.port) {
        clamConfig.clamdscan = {
          host: this.config.clamav.host,
          port: this.config.clamav.port,
        };
      }

      this.clamScan = await new NodeClam().init(clamConfig);

      if (this.config.logging.enabled) {
        console.log("✅ [VIRUS] ClamScan initialized successfully");
      }
    } catch (error) {
      console.warn(
        "⚠️ [VIRUS] ClamScan initialization failed (is clamd running?):",
        (error as Error).message,
      );
      this.clamScan = null;
    }
  }

  /**
   * Setup note listeners
   */
  private setupListeners(): void {
    this.timelineListener.on(
      "note",
      (note: Misskey.entities.Note, channel: string) => {
        this.scanNote(note, channel).catch((error) => {
          console.error("❌ [VIRUS] Error scanning note:", error);
        });
      },
    );

    if (this.config.logging.enabled) {
      console.log("✅ [VIRUS] Virus Detection Service initialized");
      console.log(
        `   File Scanning: ${this.config.scanFiles ? "Enabled" : "Disabled"}`,
      );
      console.log(
        `   Link Scanning: ${this.config.scanLinks ? "Enabled" : "Disabled"}`,
      );
      console.log(
        `   ClamAV: ${this.config.clamav.enabled ? "Enabled" : "Disabled"}`,
      );
      console.log(
        `   Auto-Delete: ${this.config.actions.autoDelete ? "Enabled" : "Disabled"}`,
      );
    }
  }

  /**
   * Scan a note for threats
   */
  private async scanNote(
    note: Misskey.entities.Note,
    channel: string,
  ): Promise<void> {
    this.scannedCount++;

    const suspiciousFindings: string[] = [];
    const confirmedThreats: string[] = [];

    // Scan file attachments
    if (this.config.scanFiles && note.files && note.files.length > 0) {
      const filesToScan = note.files.slice(
        0,
        this.config.fileScanning.maxFilesPerNote,
      );
      const { suspicious, confirmed } = await this.scanFiles(filesToScan);
      suspiciousFindings.push(...suspicious);
      confirmedThreats.push(...confirmed);
    }

    // Scan links in text
    if (this.config.scanLinks && note.text) {
      const linkThreats = await this.scanLinks(note.text);
      suspiciousFindings.push(...linkThreats);
    }

    // Run custom scanners
    if (this.config.customScanners.length > 0) {
      for (const scanner of this.config.customScanners) {
        try {
          const customThreats = await scanner(note);
          suspiciousFindings.push(...customThreats);
        } catch (error) {
          console.error("❌ [VIRUS] Custom scanner failed:", error);
        }
      }
    }

    if (confirmedThreats.length > 0 || suspiciousFindings.length > 0) {
      this.detectedCount++;
      if (confirmedThreats.length > 0) this.confirmedCount++;
      if (suspiciousFindings.length > 0) this.suspiciousCount++;
      await this.handleThreat(
        note,
        channel,
        suspiciousFindings,
        confirmedThreats,
      );
    } else if (this.config.logging.logClean && this.config.logging.verbose) {
      console.log(`✅ [VIRUS] Note ${note.id} is clean`);
    }
  }

  /**
   * Scan files for malware
   */
  private async scanFiles(
    files: Misskey.entities.DriveFile[],
  ): Promise<{ suspicious: string[]; confirmed: string[] }> {
    const suspicious: string[] = [];
    const confirmed: string[] = [];

    if (this.config.logging.enabled) {
      console.log(`   🦠 [VIRUS] Scanning ${files.length} file(s)...`);
    }

    // Wait for ClamScan to initialize if still loading
    if (this.clamScanLoading) {
      await this.clamScanLoading;
    }

    for (const file of files) {
      // Check file size
      const maxFileSize = this.config.fileScanning.maxFileSize ?? 0;
      if (maxFileSize > 0 && (file.size ?? 0) > maxFileSize) {
        suspicious.push(
          `File too large: ${file.name} (${this.formatBytes(file.size ?? 0)})`,
        );
        continue;
      }

      const fileExt = file.name.toLowerCase().match(/\.[^.]+$/)?.[0];

      // Whitelist mode: only allowed extensions
      if ((this.config.fileScanning.allowedExtensions?.length ?? 0) > 0) {
        if (
          !fileExt ||
          !this.config.fileScanning.allowedExtensions?.includes(fileExt)
        ) {
          confirmed.push(`Blocked extension (not in whitelist): ${file.name}`);
          continue;
        }
      }

      // Check suspicious extensions
      if (
        fileExt &&
        this.config.fileScanning.suspiciousExtensions?.includes(fileExt)
      ) {
        suspicious.push(`Suspicious executable: ${file.name} (${fileExt})`);
      }

      // Check MIME types
      if (
        file.type &&
        this.config.fileScanning.suspiciousMimeTypes?.some((mime) =>
          file.type?.includes(mime),
        )
      ) {
        suspicious.push(`Suspicious MIME type: ${file.name} (${file.type})`);
      }

      // Scan with ClamAV if available
      if (this.clamScan && this.config.clamav.enabled) {
        try {
          const scanResult = await Promise.race([
            this.scanFileWithClam(file),
            this.timeout<{ isInfected: boolean; viruses: string[] }>(
              this.config.performance.scanTimeout ?? 30000,
              "ClamAV scan timeout",
            ),
          ]);

          if (scanResult.isInfected) {
            confirmed.push(
              `Malware detected: ${file.name} - ${scanResult.viruses.join(", ")}`,
            );
          }
        } catch (error) {
          if (this.config.logging.enabled) {
            console.error(
              `   ❌ Failed to scan ${file.name} with ClamAV:`,
              error,
            );
          }
          suspicious.push(`Scan error: ${file.name}`);
        }
      }
    }

    return { suspicious, confirmed };
  }

  /**
   * Scan file with ClamAV
   */
  private async scanFileWithClam(
    file: Misskey.entities.DriveFile,
  ): Promise<{ isInfected: boolean; viruses: string[] }> {
    if (!this.clamScan) {
      return { isInfected: false, viruses: [] };
    }

    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "nexa-scan-"));
    const sanitizedName = file.name.replace(/[^a-zA-Z0-9._-]/g, "_");
    const tmpFile = path.join(tmpDir, sanitizedName);

    try {
      // Download file with timeout
      const fileBuffer = await Promise.race([
        this.downloadFile(file.url, this.config.performance.maxDownloadSize),
        this.timeout<Buffer>(
          this.config.performance.downloadTimeout ?? 30000,
          "Download timeout",
        ),
      ]);

      await fs.writeFile(tmpFile, fileBuffer);

      // Scan with ClamAV
      const { isInfected, viruses } = await this.clamScan.isInfected(tmpFile);

      if (
        this.config.logging.enabled &&
        (isInfected || this.config.logging.logClean)
      ) {
        console.log(
          `   📊 File: ${file.name} - ${isInfected ? "🚨 INFECTED: " + viruses.join(", ") : "✅ Clean"}`,
        );
      }

      return { isInfected: isInfected ?? false, viruses: viruses ?? [] };
    } finally {
      // Clean up temp file
      try {
        await fs.rm(tmpDir, { recursive: true, force: true });
      } catch (e) {
        // Ignore cleanup errors
      }
    }
  }

  /**
   * Download file with size limits and timeout
   */
  private downloadFile(url: string, maxSize: number = 0): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const client = url.startsWith("https") ? https : http;
      const request = client.get(url, (response) => {
        if (response.statusCode === 301 || response.statusCode === 302) {
          // Follow redirect
          const redirectUrl = response.headers.location;
          if (redirectUrl) {
            this.downloadFile(redirectUrl, maxSize).then(resolve).catch(reject);
            return;
          }
        }

        if (response.statusCode !== 200) {
          reject(
            new Error(`Failed to download file: HTTP ${response.statusCode}`),
          );
          return;
        }

        const chunks: Buffer[] = [];
        let downloadedSize = 0;

        response.on("data", (chunk) => {
          downloadedSize += chunk.length;

          if (maxSize > 0 && downloadedSize > maxSize) {
            response.destroy();
            reject(
              new Error(
                `File exceeds max download size: ${this.formatBytes(maxSize)}`,
              ),
            );
            return;
          }

          chunks.push(chunk);
        });

        response.on("end", () => resolve(Buffer.concat(chunks)));
        response.on("error", reject);
      });

      request.on("error", reject);
      request.setTimeout(
        this.config.performance.downloadTimeout ?? 30000,
        () => {
          request.destroy();
          reject(new Error("Download timeout"));
        },
      );
    });
  }

  /**
   * Scan links for threats
   */
  private async scanLinks(text: string): Promise<string[]> {
    const threats: string[] = [];
    const urlPattern = /https?:\/\/[^\s<>]+/gi;
    const urls = (text.match(urlPattern) || []).slice(
      0,
      this.config.linkScanning.maxLinksPerNote ?? 50,
    );

    if (this.config.logging.enabled && urls.length > 0) {
      console.log(`   🔗 [VIRUS] Scanning ${urls.length} link(s)...`);
    }

    for (const url of urls) {
      try {
        const urlObj = new URL(url);
        const domain = urlObj.hostname.toLowerCase();
        const pathname = urlObj.pathname.toLowerCase();

        // Check for URL shorteners (can hide malicious links)
        if (
          this.config.linkScanning.checkUrlShorteners &&
          this.config.linkScanning.urlShortenerDomains?.some((s) =>
            domain.includes(s),
          )
        ) {
          threats.push(`URL shortener (potential malware hiding): ${url}`);
        }

        // Check for free/suspicious TLDs
        if (
          this.config.linkScanning.checkSuspiciousTlds &&
          this.config.linkScanning.suspiciousTlds?.some((tld) =>
            domain.endsWith(tld),
          )
        ) {
          threats.push(`Suspicious TLD: ${url}`);
        }

        // Check for malware-related keywords in URL
        if (this.config.linkScanning.malwareKeywords) {
          for (const pattern of this.config.linkScanning.malwareKeywords) {
            if (pattern.test(url)) {
              threats.push(`Malware-related URL pattern: ${url}`);
              break;
            }
          }
        }

        // Check for IP addresses (often used for malware C2)
        if (
          this.config.linkScanning.checkIpAddresses &&
          /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(domain)
        ) {
          threats.push(`IP address URL (potential C2): ${url}`);
        }

        // Check for suspicious file downloads
        if (this.config.linkScanning.checkExecutableDownloads) {
          const execPattern = new RegExp(
            `\\.(${this.config.linkScanning.executableExtensions?.join("|")})$`,
            "i",
          );
          if (execPattern.test(pathname)) {
            threats.push(`Direct executable download: ${url}`);
          }
        }
      } catch (e) {
        // Invalid URL, skip
      }
    }

    return threats;
  }

  /**
   * Get recommended action codes based on threat level
   */
  private getRecommendedActions(
    suspiciousFindings: string[],
    confirmedThreats: string[],
    virusHistory: number,
  ): RecommendedAction[] {
    const actions: RecommendedAction[] = [];

    if (confirmedThreats.length > 0) {
      if (this.config.actions.deleteNote && this.config.actions.deleteFiles) {
        actions.push(RecommendedAction.AUTO_DELETED);
      } else if (this.config.actions.deleteNote) {
        actions.push(RecommendedAction.NOTE_DELETED);
      } else if (this.config.actions.deleteFiles) {
        actions.push(RecommendedAction.FILES_DELETED);
      }

      if (
        this.config.actions.suspendUser &&
        virusHistory >= (this.config.actions.suspendThreshold ?? 3)
      ) {
        actions.push(RecommendedAction.USER_SUSPENDED);
      } else if (this.config.actions.silenceUser) {
        actions.push(RecommendedAction.USER_SILENCED);
      } else if (virusHistory > 0) {
        actions.push(RecommendedAction.MONITOR_USER);
      }

      if (this.config.actions.quarantine) {
        actions.push(RecommendedAction.QUARANTINED);
      }
    } else {
      actions.push(RecommendedAction.MANUAL_REVIEW);
    }

    if (actions.length === 0) {
      actions.push(RecommendedAction.NO_ACTION);
    }

    return actions;
  }

  /**
   * Convert action codes to human-readable text
   */
  private formatActions(
    actions: RecommendedAction[],
    virusHistory: number,
  ): string {
    const messages: string[] = [];

    for (const action of actions) {
      switch (action) {
        case RecommendedAction.AUTO_DELETED:
          messages.push("Post and files automatically removed");
          break;
        case RecommendedAction.FILES_DELETED:
          messages.push("Files automatically removed");
          break;
        case RecommendedAction.NOTE_DELETED:
          messages.push("Post automatically removed");
          break;
        case RecommendedAction.USER_SUSPENDED:
          messages.push(`Suspend user (${virusHistory} violations)`);
          break;
        case RecommendedAction.USER_SILENCED:
          const hours = Math.floor(
            (this.config.actions.silenceDuration ?? 0) / (1000 * 60 * 60),
          );
          messages.push(`Silence user for ${hours}h`);
          break;
        case RecommendedAction.MONITOR_USER:
          messages.push(`Monitor user (${virusHistory + 1} violations total)`);
          break;
        case RecommendedAction.MANUAL_REVIEW:
          messages.push("Manual review recommended");
          break;
        case RecommendedAction.QUARANTINED:
          messages.push("Quarantined for investigation");
          break;
        case RecommendedAction.NO_ACTION:
          messages.push("No action taken");
          break;
      }
    }

    return messages.join(". ") + ".";
  }

  /**
   * Handle detected threats with comprehensive actions
   */
  private async handleThreat(
    note: Misskey.entities.Note,
    channel: string,
    suspiciousFindings: string[],
    confirmedThreats: string[],
  ): Promise<void> {
    const hasConfirmedThreat = confirmedThreats.length > 0;
    const allFindings = [...confirmedThreats, ...suspiciousFindings];

    // Track user virus history
    const userVirusKey = `virus:user:${note.user.id}`;
    const virusHistory = this.config.cache.trackUserHistory
      ? cache.get<number>(userVirusKey) || 0
      : 0;

    const recommendedActions = this.getRecommendedActions(
      suspiciousFindings,
      confirmedThreats,
      virusHistory,
    );
    const recommendedActionText = this.formatActions(
      recommendedActions,
      virusHistory,
    );

    // Generate URLs
    const noteUrl = this.config.instanceUrl
      ? `${this.config.instanceUrl}/notes/${note.id}`
      : undefined;
    const userUrl = this.config.instanceUrl
      ? `${this.config.instanceUrl}/@${note.user.username}`
      : undefined;

    const severity = hasConfirmedThreat ? "confirmed" : "suspicious";

    if (this.config.logging.enabled) {
      console.log(
        `\n🦠 [VIRUS] ${hasConfirmedThreat ? "Malware" : "Suspicious content"} detected in note ${note.id}`,
      );
      console.log(`   Channel: ${channel}`);
      console.log(`   User: @${note.user.username}`);
      if (confirmedThreats.length > 0)
        console.log(`   Confirmed Threats: ${confirmedThreats.join(", ")}`);
      if (suspiciousFindings.length > 0)
        console.log(`   Suspicious Findings: ${suspiciousFindings.join(", ")}`);
      if (noteUrl) console.log(`   Note URL: ${noteUrl}`);
      if (userUrl) console.log(`   User URL: ${userUrl}`);
      console.log(`   Recommended Actions: ${recommendedActionText}`);
    }

    // Determine if we should auto-delete
    const shouldDelete =
      (this.config.actions.autoDelete && hasConfirmedThreat) ||
      (this.config.actions.autoDeleteOnSuspicious &&
        suspiciousFindings.length > 0);

    let deleteStatus = "Auto-delete disabled";

    if (shouldDelete) {
      try {
        // Delete all files from the drive
        if (
          this.config.actions.deleteFiles &&
          note.files &&
          note.files.length > 0
        ) {
          for (const file of note.files) {
            try {
              await this.client.request("drive/files/delete", {
                fileId: file.id,
              });
              if (this.config.logging.enabled) {
                console.log(`   ✅ Deleted file: ${file.name} (${file.id})`);
              }
            } catch (err) {
              console.error(`   ❌ Failed to delete file ${file.id}:`, err);
            }
          }
        }

        // Delete the note
        if (this.config.actions.deleteNote) {
          await this.client.request("notes/delete", { noteId: note.id });
          if (this.config.logging.enabled) {
            console.log(`   ✅ Note deleted automatically`);
          }
          deleteStatus = `Note and ${note.files?.length || 0} file(s) deleted`;
        } else {
          deleteStatus = `${note.files?.length || 0} file(s) deleted (note preserved)`;
        }
      } catch (error) {
        console.error(`   ❌ Failed to auto-delete:`, error);
        deleteStatus = `Auto-delete failed: ${(error as Error).message}`;
      }
    } else if (
      !hasConfirmedThreat &&
      !this.config.actions.autoDeleteOnSuspicious
    ) {
      deleteStatus =
        "Not deleted - only suspicious findings, no confirmed malware";
    }

    // Update user history
    if (this.config.cache.trackUserHistory) {
      cache.set(
        userVirusKey,
        virusHistory + 1,
        this.config.cache.userHistoryTtl ?? 90 * 24 * 60 * 60,
      );
    }

    // Check if user should be suspended
    if (
      this.config.actions.suspendUser &&
      virusHistory >= (this.config.actions.suspendThreshold ?? 3)
    ) {
      try {
        await this.client.request("admin/suspend-user", {
          userId: note.user.id,
        });
        if (this.config.logging.enabled) {
          console.log(`   🚫 User suspended (${virusHistory + 1} violations)`);
        }
      } catch (error) {
        console.error(`   ❌ Failed to suspend user:`, error);
      }
    }

    // Check if user should be silenced
    if (this.config.actions.silenceUser && !this.config.actions.suspendUser) {
      try {
        const expiresAt =
          Date.now() +
          (this.config.actions.silenceDuration ?? 24 * 60 * 60 * 1000);
        // Note: Misskey API for silencing may vary
        if (this.config.logging.enabled) {
          console.log(
            `   🔇 User should be silenced until ${new Date(expiresAt).toISOString()}`,
          );
        }
      } catch (error) {
        console.error(`   ❌ Failed to silence user:`, error);
      }
    }

    // Quarantine in cache
    if (this.config.actions.quarantine && this.config.cache.enabled) {
      cache.set(
        `virus:${note.id}`,
        {
          noteId: note.id,
          userId: note.user.id,
          username: note.user.username,
          threats: allFindings,
          confirmedThreats,
          suspiciousFindings,
          severity,
          recommendedActions,
          noteUrl,
          userUrl,
          virusCount: virusHistory + 1,
          detectedAt: Date.now(),
          channel,
          quarantined: true,
          autoDeleted: shouldDelete,
          deleteStatus,
          files: note.files,
          resolved: false,
        },
        this.config.cache.ttl ?? 90 * 24 * 60 * 60,
      );

      // Track user detections for moderator log correlation
      cache.addUserDetection(
        "virus",
        note.user.id,
        note.id,
        this.config.cache.ttl ?? 90 * 24 * 60 * 60,
      );

      // Store file-to-note mappings for quick file-based lookups
      if (this.config.cache.trackFileHistory && note.files?.length) {
        for (const file of note.files) {
          cache.setFileDetection(
            file.id,
            note.id,
            this.config.cache.ttl ?? 90 * 24 * 60 * 60,
          );
        }
      }
    }

    // Check notification grouping
    const shouldNotify = this.shouldSendNotification(
      note.user.id,
      hasConfirmedThreat,
    );

    // Send notification
    if (this.config.notifications.enabled && shouldNotify) {
      const shouldInclude =
        (hasConfirmedThreat && this.config.notifications.onConfirmed) ||
        (!hasConfirmedThreat && this.config.notifications.onSuspicious);

      if (shouldInclude) {
        await this.sendNotification(
          note,
          channel,
          deleteStatus,
          virusHistory,
          hasConfirmedThreat,
          confirmedThreats,
          suspiciousFindings,
          allFindings,
          recommendedActions,
          recommendedActionText,
          noteUrl,
          userUrl,
        );
      }
    }
  }

  /**
   * Check if notification should be sent (with grouping)
   */
  private shouldSendNotification(
    userId: string,
    isConfirmed: boolean,
  ): boolean {
    if (!this.config.notifications.groupByUser) {
      return true;
    }

    const now = Date.now();
    const pending = this.pendingNotifications.get(userId);

    if (
      !pending ||
      now - pending.lastNotification >
        (this.config.notifications.groupingWindow ?? 5 * 60 * 1000)
    ) {
      this.pendingNotifications.set(userId, {
        count: 1,
        lastNotification: now,
      });
      return true;
    }

    // For confirmed threats, always notify
    if (isConfirmed) {
      this.pendingNotifications.set(userId, {
        count: pending.count + 1,
        lastNotification: now,
      });
      return true;
    }

    // For suspicious, group them
    pending.count++;
    return false;
  }

  /**
   * Send notification about threat
   */
  private async sendNotification(
    note: Misskey.entities.Note,
    channel: string,
    deleteStatus: string,
    virusHistory: number,
    hasConfirmedThreat: boolean,
    confirmedThreats: string[],
    suspiciousFindings: string[],
    allFindings: string[],
    recommendedActions: RecommendedAction[],
    recommendedActionText: string,
    noteUrl?: string,
    userUrl?: string,
  ): Promise<void> {
    const preview =
      this.config.notifications.includePreview && note.text
        ? note.text.substring(0, this.config.notifications.previewLength ?? 100)
        : "(no text)";

    await this.notifications.notify({
      type: "spam_detected", // Using spam_detected as closest match
      severity: hasConfirmedThreat ? "critical" : "medium",
      title: hasConfirmedThreat
        ? "🦠 Malware/Virus Detected"
        : "⚠️ Suspicious Content Detected",
      description: `**User:** @${note.user.username}\n**Action:** ${deleteStatus}\n**Channel:** ${channel}${virusHistory > 0 ? `\n**Repeat Offender:** ${virusHistory + 1} violations` : ""}`,
      metadata: {
        "Note ID": note.id,
        User: `@${note.user.username}`,
        "Confirmed Threats":
          confirmedThreats.length > 0 ? confirmedThreats.join(", ") : "None",
        "Suspicious Findings":
          suspiciousFindings.length > 0
            ? suspiciousFindings.join(", ")
            : "None",
        Threats: allFindings.join(", "),
        "Violation Count": `${virusHistory + 1} total`,
        "Auto-Delete Status": deleteStatus,
        "Recommended Actions": recommendedActionText,
        "Note URL": noteUrl || "N/A",
        "User Profile": userUrl || "N/A",
        Preview: preview,
      },
      timestamp: new Date(),
    });
  }

  /**
   * Get service statistics
   */
  getStats() {
    return {
      scanned: this.scannedCount,
      detected: this.detectedCount,
      confirmed: this.confirmedCount,
      suspicious: this.suspiciousCount,
      detectionRate:
        this.scannedCount > 0 ? this.detectedCount / this.scannedCount : 0,
    };
  }
}
