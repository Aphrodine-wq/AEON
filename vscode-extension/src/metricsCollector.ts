/**
 * Metrics collector for tracking AEON performance and usage
 */
export class MetricsCollector {
    private metrics = {
        totalVerifications: 0,
        successfulVerifications: 0,
        failedVerifications: 0,
        totalDurationMs: 0,
        minDurationMs: Infinity,
        maxDurationMs: 0,
        totalErrors: 0,
        cacheHits: 0,
        cacheMisses: 0,
        projectVerifications: 0,
        realTimeVerifications: 0,
        byLanguage: new Map<string, {
            count: number;
            totalDuration: number;
            errors: number;
        }>(),
        byHour: new Map<number, number>(),
        verificationHistory: [] as Array<{
            timestamp: number;
            duration: number;
            success: boolean;
            errors: number;
            language: string;
        }>
    };

    constructor(private outputChannel: any) {}

    recordVerification(success: boolean, durationMs: number, errorCount: number = 0, language: string = 'unknown'): void {
        this.metrics.totalVerifications++;
        this.metrics.totalDurationMs += durationMs;
        
        if (success) {
            this.metrics.successfulVerifications++;
        } else {
            this.metrics.failedVerifications++;
            this.metrics.totalErrors += errorCount;
        }

        this.metrics.minDurationMs = Math.min(this.metrics.minDurationMs, durationMs);
        this.metrics.maxDurationMs = Math.max(this.metrics.maxDurationMs, durationMs);

        // Track by language
        if (!this.metrics.byLanguage.has(language)) {
            this.metrics.byLanguage.set(language, { count: 0, totalDuration: 0, errors: 0 });
        }
        const langMetrics = this.metrics.byLanguage.get(language)!;
        langMetrics.count++;
        langMetrics.totalDuration += durationMs;
        if (!success) {
            langMetrics.errors += errorCount;
        }

        // Track by hour
        const hour = new Date().getHours();
        this.metrics.byHour.set(hour, (this.metrics.byHour.get(hour) || 0) + 1);

        // Keep history (last 100 entries)
        this.metrics.verificationHistory.push({
            timestamp: Date.now(),
            duration: durationMs,
            success,
            errors: errorCount,
            language
        });

        if (this.metrics.verificationHistory.length > 100) {
            this.metrics.verificationHistory.shift();
        }
    }

    recordProjectVerification(result: any): void {
        this.metrics.projectVerifications++;
        this.recordVerification(
            result.total_errors === 0,
            result.duration_ms,
            result.total_errors,
            'project'
        );
    }

    recordRealTimeVerification(success: boolean, durationMs: number): void {
        this.metrics.realTimeVerifications++;
        this.recordVerification(success, durationMs, 0, 'realtime');
    }

    recordCacheHit(hit: boolean): void {
        if (hit) {
            this.metrics.cacheHits++;
        } else {
            this.metrics.cacheMisses++;
        }
    }

    getMetrics(): any {
        const avgDuration = this.metrics.totalVerifications > 0 
            ? Math.round(this.metrics.totalDurationMs / this.metrics.totalVerifications)
            : 0;

        const cacheTotal = this.metrics.cacheHits + this.metrics.cacheMisses;
        const cacheHitRate = cacheTotal > 0 
            ? Math.round((this.metrics.cacheHits / cacheTotal) * 100)
            : 0;

        const errorRate = this.metrics.totalVerifications > 0
            ? Math.round((this.metrics.failedVerifications / this.metrics.totalVerifications) * 100)
            : 0;

        return {
            ...this.metrics,
            averageDurationMs: avgDuration,
            cacheHitRate,
            errorRate,
            languageBreakdown: Array.from(this.metrics.byLanguage.entries()).map(([lang, stats]) => ({
                language: lang,
                count: stats.count,
                avgDuration: Math.round(stats.totalDuration / stats.count),
                errorCount: stats.errors
            })),
            hourlyActivity: Array.from(this.metrics.byHour.entries())
                .map(([hour, count]) => ({ hour, count }))
                .sort((a, b) => a.hour - b.hour)
        };
    }

    exportMetrics(): string {
        const metrics = this.getMetrics();
        return JSON.stringify(metrics, null, 2);
    }

    reset(): void {
        this.metrics = {
            totalVerifications: 0,
            successfulVerifications: 0,
            failedVerifications: 0,
            totalDurationMs: 0,
            minDurationMs: Infinity,
            maxDurationMs: 0,
            totalErrors: 0,
            cacheHits: 0,
            cacheMisses: 0,
            projectVerifications: 0,
            realTimeVerifications: 0,
            byLanguage: new Map(),
            byHour: new Map(),
            verificationHistory: []
        };
    }
}
