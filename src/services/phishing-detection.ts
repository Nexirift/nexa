import * as Misskey from "@nexirift/pulsar-js";
import { TimelineListener } from "../modules/timeline-listener";
import { cache } from "../modules/cache";
import { NotificationManager } from "../notifiers";

export interface PhishingDetectionOptions {
  checkUrls?: boolean;
  checkSuspiciousKeywords?: boolean;
  checkDomainAge?: boolean;
  blockKnownPhishing?: boolean;
  instanceUrl?: string;
}

/**
 * Phishing Detection Service
 * Detects phishing attempts and credential harvesting
 */
export class PhishingDetectionService {
  private detectedCount = 0;
  private scannedCount = 0;
  private knownPhishingDomains: Set<string> = new Set();

  constructor(
    private timelineListener: TimelineListener,
    private notifications: NotificationManager,
    private options: PhishingDetectionOptions = {},
  ) {
    this.options = {
      checkUrls: true,
      checkSuspiciousKeywords: true,
      checkDomainAge: false,
      blockKnownPhishing: true,
      ...options,
    };
    this.setupListeners();
    this.loadKnownPhishingDomains();
  }

  private setupListeners(): void {
    this.timelineListener.on(
      "note",
      (note: Misskey.entities.Note, channel: string) => {
        this.scanNote(note, channel);
      },
    );

    console.log("Phishing Detection Service initialized");
  }

  private loadKnownPhishingDomains(): void {
    // Load from cache or database
    // In production, this would be updated from a threat intelligence feed
    this.knownPhishingDomains = new Set([
      // URL shorteners (can hide phishing)
      "bit.ly",
      "tinyurl.com",
      "goo.gl",
      "t.co",
      "ow.ly",
      "shorturl.at",
      "rb.gy",
      "cutt.ly",
      "tiny.cc",
      "is.gd",
      "cli.gs",
      "pic.gd",
      "v.gd",

      // Common phishing TLDs
      "tk",
      "ml",
      "ga",
      "cf",
      "gq",
    ]);
  }

  private async scanNote(
    note: Misskey.entities.Note,
    channel: string,
  ): Promise<void> {
    this.scannedCount++;

    if (!note.text) return;

    const phishingIndicators: string[] = [];
    let riskScore = 0;

    // Extract URLs
    const urlPattern = /https?:\/\/[^\s<>]+/gi;
    const urls = note.text.match(urlPattern) || [];

    for (const url of urls) {
      // Check against known phishing domains
      const knownPhishing = this.checkKnownPhishing(url);
      if (knownPhishing.isPhishing) {
        phishingIndicators.push(knownPhishing.reason);
        riskScore += knownPhishing.score;
      }

      // Check for domain spoofing
      const spoofing = this.checkDomainSpoofing(url);
      if (spoofing.isPhishing) {
        phishingIndicators.push(spoofing.reason);
        riskScore += spoofing.score;
      }

      // Check for suspicious URL patterns
      const suspiciousUrl = this.checkSuspiciousUrlPatterns(url);
      if (suspiciousUrl.isPhishing) {
        phishingIndicators.push(suspiciousUrl.reason);
        riskScore += suspiciousUrl.score;
      }
    }

    // Check for credential harvesting keywords
    if (this.options.checkSuspiciousKeywords) {
      const keywordCheck = this.checkPhishingKeywords(note.text);
      if (keywordCheck.isPhishing) {
        phishingIndicators.push(keywordCheck.reason);
        riskScore += keywordCheck.score;
      }
    }

    if (riskScore >= 2) {
      // Threshold
      this.detectedCount++;
      await this.handlePhishing(note, channel, phishingIndicators, riskScore);
    }
  }

  private checkKnownPhishing(url: string): {
    isPhishing: boolean;
    reason: string;
    score: number;
  } {
    try {
      const urlObj = new URL(url);
      const domain = urlObj.hostname.toLowerCase();

      if (this.knownPhishingDomains.has(domain)) {
        return {
          isPhishing: true,
          reason: `Known phishing domain: ${domain}`,
          score: 3,
        };
      }

      // Temporarily disabled to reduce false positives
      // Check for URL shorteners (can hide phishing)
      // const shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly'];
      // if (shorteners.some(s => domain.includes(s))) {
      //     return {
      //         isPhishing: true,
      //         reason: `URL shortener detected: ${domain}`,
      //         score: 1
      //     };
      // }
    } catch (e) {
      // Invalid URL
    }

    return { isPhishing: false, reason: "", score: 0 };
  }

  private checkDomainSpoofing(url: string): {
    isPhishing: boolean;
    reason: string;
    score: number;
  } {
    try {
      const urlObj = new URL(url);
      const domain = urlObj.hostname.toLowerCase();

      // Check for homograph attacks (unicode lookalikes)
      if (/[а-яА-Я]/.test(domain)) {
        // Cyrillic characters
        return {
          isPhishing: true,
          reason: "Homograph attack detected (Cyrillic lookalikes)",
          score: 3,
        };
      }

      // Check for Greek characters
      if (/[α-ωΑ-Ω]/.test(domain)) {
        return {
          isPhishing: true,
          reason: "Homograph attack detected (Greek lookalikes)",
          score: 3,
        };
      }

      // Common brand typosquatting patterns
      const brandPatterns = [
        // Major brands with common substitutions
        { pattern: /pay?pa[l1]/, brands: ["paypal"], score: 3 },
        { pattern: /g[o0]{2}gle/, brands: ["google"], score: 3 },
        { pattern: /faceb[o0]{2}k/, brands: ["facebook"], score: 3 },
        { pattern: /micr[o0]s[o0]ft/, brands: ["microsoft"], score: 3 },
        { pattern: /app[l1]e/, brands: ["apple"], score: 3 },
        { pattern: /tw[i1]tter/, brands: ["twitter"], score: 3 },
        { pattern: /amaz[o0]n/, brands: ["amazon"], score: 3 },
        { pattern: /netf[l1]ix/, brands: ["netflix"], score: 3 },

        // Financial institutions
        { pattern: /bank.*[o0]f/, brands: ["bank"], score: 2 },
        { pattern: /paypa[l1]/, brands: ["paypal"], score: 3 },
        { pattern: /venm[o0]/, brands: ["venmo"], score: 2 },
        { pattern: /cash.*app/, brands: ["cashapp"], score: 2 },
      ];

      for (const { pattern, brands, score } of brandPatterns) {
        if (pattern.test(domain)) {
          // Check if it's actually the legitimate domain
          const isLegit = brands.some(
            (brand) =>
              domain.includes(`${brand}.com`) ||
              domain.includes(`${brand}.net`) ||
              domain.includes(`${brand}.org`),
          );

          if (!isLegit) {
            return {
              isPhishing: true,
              reason: `Typosquatting: ${domain} (impersonating ${brands.join("/")})`,
              score,
            };
          }
        }
      }

      // // Phishing-related subdomains
      // const phishingSubdomains = [
      //   /^(verify|secure|login|account|update|confirm|validate)\./i,
      //   /^(signin|auth|authentication|password|reset)\./i,
      //   /^(support|help|security|billing|payment)\./i,
      // ];

      // for (const pattern of phishingSubdomains) {
      //   if (pattern.test(domain)) {
      //     return {
      //       isPhishing: true,
      //       reason: `Suspicious subdomain: ${domain}`,
      //       score: 2,
      //     };
      //   }
      // }

      // Check for excessive subdomains (hiding real domain)
      const parts = domain.split(".");
      if (parts.length > 4) {
        return {
          isPhishing: true,
          reason: `Excessive subdomains: ${domain} (${parts.length} levels)`,
          score: 1,
        };
      }

      // Check for suspicious TLD combinations
      const tld = parts[parts.length - 1];
      const sld = parts[parts.length - 2];

      // Free TLDs with brand names
      const freeTlds = ["tk", "ml", "ga", "cf", "gq", "top", "buzz", "xyz"];
      const commonBrands = [
        "google",
        "microsoft",
        "apple",
        "amazon",
        "paypal",
        "facebook",
      ];

      if (
        freeTlds.includes(tld) &&
        commonBrands.some((brand) => sld?.includes(brand))
      ) {
        return {
          isPhishing: true,
          reason: `Brand name on free TLD: ${domain}`,
          score: 2,
        };
      }
    } catch (e) {
      // Invalid URL
    }

    return { isPhishing: false, reason: "", score: 0 };
  }

  private checkSuspiciousUrlPatterns(url: string): {
    isPhishing: boolean;
    reason: string;
    score: number;
  } {
    const suspiciousPatterns = [
      {
        pattern: /@/,
        reason: "URL contains @ (can hide real domain)",
        score: 2,
      },
      {
        pattern: /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/,
        reason: "IP address instead of domain",
        score: 2,
      },
      {
        pattern: /\.tk$|\.ml$|\.ga$|\.cf$|\.gq$/i,
        reason: "Free TLD commonly used for phishing",
        score: 1,
      },
      {
        pattern: /\.(zip|rar|exe|scr|bat|cmd)$/i,
        reason: "Direct download of executable",
        score: 2,
      },
      {
        pattern: /data:text\/html/i,
        reason: "Data URI (can contain phishing page)",
        score: 3,
      },
      {
        pattern: /javascript:/i,
        reason: "JavaScript URI (potential XSS)",
        score: 3,
      },
    ];

    for (const { pattern, reason, score } of suspiciousPatterns) {
      if (pattern.test(url)) {
        return { isPhishing: true, reason, score };
      }
    }

    // Check URL length (very long URLs often hide malicious content)
    if (url.length > 200) {
      return {
        isPhishing: true,
        reason: `Unusually long URL (${url.length} chars)`,
        score: 1,
      };
    }

    // Check for excessive path depth
    try {
      const urlObj = new URL(url);
      const pathDepth = urlObj.pathname
        .split("/")
        .filter((p) => p.length > 0).length;

      if (pathDepth > 5) {
        return {
          isPhishing: true,
          reason: `Excessive path depth (${pathDepth} levels)`,
          score: 1,
        };
      }
    } catch (e) {
      // Invalid URL
    }

    return { isPhishing: false, reason: "", score: 0 };
  }

  private checkPhishingKeywords(text: string): {
    isPhishing: boolean;
    reason: string;
    score: number;
  } {
    const phishingPatterns = [
      // Urgency tactics (high pressure)
      {
        pattern:
          /\b(urgent|immediately|act now|right now|limited time|expires? (soon|today|tonight))\b/i,
        reason: "Urgency tactics",
        score: 1,
      },
      {
        pattern:
          /\b(last chance|final (notice|warning)|don't miss out|hurry)\b/i,
        reason: "Pressure tactics",
        score: 1,
      },

      // Credential/account requests
      {
        pattern:
          /\b(verify|confirm|update|validate)\b.*\b(account|identity|password|credentials|information)\b/i,
        reason: "Credential verification request",
        score: 2,
      },
      {
        pattern: /\b(reset|recover|change)\b.*\b(password|account|access)\b/i,
        reason: "Password reset social engineering",
        score: 2,
      },
      {
        pattern: /\b(re-?enable|restore|unlock)\b.*\b(account|access)\b/i,
        reason: "Account restoration scam",
        score: 2,
      },

      // Payment/financial
      {
        pattern:
          /\b(update|verify|confirm)\b.*\b(payment|billing|card|credit card)\b/i,
        reason: "Payment information phishing",
        score: 2,
      },
      {
        pattern:
          /\b(refund|reimbursement|compensation)\b.*\b(claim|receive|get)\b/i,
        reason: "Fake refund scam",
        score: 1,
      },

      // Security threats
      {
        pattern:
          /\b(suspended|locked|disabled|blocked|restricted)\b.*\b(account|access)\b/i,
        reason: "Account suspension threat",
        score: 2,
      },
      {
        pattern:
          /\b(unauthorized|suspicious|unusual)\b.*\b(activity|access|login|transaction)\b/i,
        reason: "Fake security alert",
        score: 2,
      },
      {
        pattern:
          /\b(security (alert|warning|notice)|your account (is )?at risk)\b/i,
        reason: "Security scare tactics",
        score: 2,
      },

      // Prize/reward scams
      {
        pattern:
          /\b(you('?ve)? won|winner|selected|chosen)\b.*\b(prize|reward|gift|\$\d+)\b/i,
        reason: "Fake prize notification",
        score: 2,
      },
      {
        pattern: /\b(claim|collect|receive)\b.*\b(prize|reward|winnings)\b/i,
        reason: "Prize claiming scam",
        score: 1,
      },

      // Impersonation
      {
        pattern:
          /\b(from|message from|notification from)\b.*\b(admin|administrator|moderator|support|team)\b/i,
        reason: "Admin/staff impersonation",
        score: 1,
      },
    ];

    let totalScore = 0;
    const matchedReasons: string[] = [];

    for (const { pattern, reason, score } of phishingPatterns) {
      if (pattern.test(text)) {
        totalScore += score;
        matchedReasons.push(reason);
      }
    }

    if (totalScore > 0) {
      return {
        isPhishing: true,
        reason: `Phishing indicators: ${matchedReasons.join(", ")}`,
        score: Math.min(totalScore, 3), // Cap at 3
      };
    }

    return { isPhishing: false, reason: "", score: 0 };
  }

  private getRecommendedActions(
    note: Misskey.entities.Note,
    score: number,
    indicators: string[],
  ): string {
    return "Delete the content. If constantly repeated, suspend the user.";
  }

  private async handlePhishing(
    note: Misskey.entities.Note,
    channel: string,
    indicators: string[],
    score: number,
  ): Promise<void> {
    const recommendedAction = this.getRecommendedActions(
      note,
      score,
      indicators,
    );

    // Generate URLs
    const noteUrl = this.options.instanceUrl
      ? `${this.options.instanceUrl}/notes/${note.id}`
      : undefined;
    const userUrl = this.options.instanceUrl
      ? `${this.options.instanceUrl}/@${note.user.username}`
      : undefined;

    console.log(`\n🎣 [PHISHING] Detected in note ${note.id}`);
    console.log(`   Channel: ${channel}`);
    console.log(`   User: @${note.user.username}`);
    console.log(`   Risk Score: ${score}`);
    console.log(`   Indicators: ${indicators.join(", ")}`);
    if (noteUrl) console.log(`   Note URL: ${noteUrl}`);
    if (userUrl) console.log(`   User URL: ${userUrl}`);
    console.log(`   Recommended Action: ${recommendedAction}`);

    // Track user phishing attempts
    const userPhishingKey = `phishing:user:${note.user.id}`;
    const phishingHistory = cache.get<number>(userPhishingKey) || 0;
    cache.set(userPhishingKey, phishingHistory + 1, 90 * 24 * 60 * 60); // 90 days

    // Flag in cache
    cache.set(
      `phishing:${note.id}`,
      {
        noteId: note.id,
        userId: note.user.id,
        username: note.user.username,
        indicators,
        score,
        recommendedAction,
        noteUrl,
        userUrl,
        phishingCount: phishingHistory + 1,
        detectedAt: Date.now(),
        channel,
        resolved: false,
      },
      30 * 24 * 60 * 60,
    ); // 30 days

    // Track user detections for moderator log correlation
    cache.addUserDetection(
      "phishing",
      note.user.id,
      note.id,
      30 * 24 * 60 * 60,
    );

    // Send notification
    const severity = score >= 4 ? "critical" : score >= 3 ? "high" : "medium";
    await this.notifications.notify({
      type: "spam_detected", // Using spam_detected as closest match
      severity,
      title: "🎣 Phishing Attempt Detected",
      description: `**User:** @${note.user.username}\n**Risk Score:** ${score}\n**Channel:** ${channel}${phishingHistory > 0 ? `\n**Repeat Offender:** ${phishingHistory + 1} attempts` : ""}`,
      metadata: {
        "Note ID": note.id,
        User: `@${note.user.username}`,
        "Risk Score": `${score}/5`,
        Indicators: indicators.join(", "),
        "Attempt Count": `${phishingHistory + 1} total`,
        "Recommended Action": recommendedAction,
        "Note URL": noteUrl || "N/A",
        "User Profile": userUrl || "N/A",
        Preview: note.text?.substring(0, 100) || "(no text)",
      },
      timestamp: new Date(),
    });
  }

  getStats() {
    return {
      scanned: this.scannedCount,
      detected: this.detectedCount,
      detectionRate:
        this.scannedCount > 0 ? this.detectedCount / this.scannedCount : 0,
    };
  }

  /**
   * Add a domain to the known phishing list
   */
  addPhishingDomain(domain: string): void {
    this.knownPhishingDomains.add(domain.toLowerCase());
  }

  /**
   * Remove a domain from the known phishing list
   */
  removePhishingDomain(domain: string): void {
    this.knownPhishingDomains.delete(domain.toLowerCase());
  }
}
