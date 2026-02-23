import * as vscode from 'vscode';

/**
 * Analyzes entire workspace for verification insights
 */
export class ProjectAnalyzer {
    private analysisCache = new Map<string, any>();
    private readonly cacheExpiryMs = 5 * 60 * 1000; // 5 minutes

    constructor(private outputChannel: vscode.OutputChannel) {}

    async analyzeWorkspace(): Promise<void> {
        if (!vscode.workspace.workspaceFolders) {
            return;
        }

        const workspaceFolder = vscode.workspace.workspaceFolders[0];
        const cacheKey = workspaceFolder.uri.toString();
        
        // Check cache
        const cached = this.analysisCache.get(cacheKey);
        if (cached && Date.now() - cached.timestamp < this.cacheExpiryMs) {
            return;
        }

        try {
            this.outputChannel.appendLine('Analyzing workspace...');
            
            // Get all supported files
            const files = await this._getAllSupportedFiles();
            
            // Analyze file types and complexity
            const analysis = {
                totalFiles: files.length,
                languages: this._analyzeLanguages(files),
                complexity: await this._analyzeComplexity(files),
                dependencies: await this._analyzeDependencies(files),
                verificationReadiness: await this._assessVerificationReadiness(files)
            };

            this.analysisCache.set(cacheKey, {
                ...analysis,
                timestamp: Date.now()
            });

            this.outputChannel.appendLine(`Workspace analysis complete: ${files.length} files analyzed`);
            
        } catch (error) {
            this.outputChannel.appendLine(`Workspace analysis failed: ${error}`);
        }
    }

    private async _getAllSupportedFiles(): Promise<vscode.Uri[]> {
        const supportedExtensions = [
            '.py', '.java', '.js', '.jsx', '.ts', '.tsx', 
            '.go', '.rs', '.c', '.cpp', '.h', '.hpp',
            '.rb', '.swift', '.kt', '.php', '.scala', '.dart'
        ];

        const files: vscode.Uri[] = [];
        
        for (const folder of vscode.workspace.workspaceFolders || []) {
            const pattern = new vscode.RelativePattern(folder, '**/*');
            const found = await vscode.workspace.findFiles(pattern, '**/node_modules/**');
            
            files.push(...found.filter(file => 
                supportedExtensions.some(ext => file.path.endsWith(ext))
            ));
        }

        return files;
    }

    private _analyzeLanguages(files: vscode.Uri[]): Record<string, number> {
        const languages: Record<string, number> = {};
        
        files.forEach(file => {
            const ext = file.path.split('.').pop();
            const languageMap: Record<string, string> = {
                'py': 'Python',
                'java': 'Java',
                'js': 'JavaScript',
                'jsx': 'JavaScript',
                'ts': 'TypeScript',
                'tsx': 'TypeScript',
                'go': 'Go',
                'rs': 'Rust',
                'c': 'C',
                'cpp': 'C++',
                'h': 'C/C++',
                'hpp': 'C++',
                'rb': 'Ruby',
                'swift': 'Swift',
                'kt': 'Kotlin',
                'php': 'PHP',
                'scala': 'Scala',
                'dart': 'Dart'
            };
            
            const lang = languageMap[ext || ''] || 'Other';
            languages[lang] = (languages[lang] || 0) + 1;
        });

        return languages;
    }

    private async _analyzeComplexity(files: vscode.Uri[]): Promise<any> {
        const complexity = {
            totalLines: 0,
            totalFunctions: 0,
            totalClasses: 0,
            averageLinesPerFile: 0,
            largeFiles: 0
        };

        for (const file of files.slice(0, 100)) { // Limit to avoid blocking
            try {
                const content = await vscode.workspace.fs.readFile(file);
                const text = Buffer.from(content).toString('utf-8');
                const lines = text.split('\n').length;
                
                complexity.totalLines += lines;
                
                // Simple heuristics for functions and classes
                complexity.totalFunctions += (text.match(/\b(function|def|func|fn)\s+\w+/g) || []).length;
                complexity.totalClasses += (text.match(/\b(class|struct|interface)\s+\w+/g) || []).length;
                
                if (lines > 500) {
                    complexity.largeFiles++;
                }
            } catch (error) {
                // Skip files that can't be read
            }
        }

        complexity.averageLinesPerFile = Math.round(complexity.totalLines / files.length);
        
        return complexity;
    }

    private async _analyzeDependencies(files: vscode.Uri[]): Promise<any> {
        const dependencies = {
            imports: new Map<string, number>(),
            externalLibraries: new Set<string>(),
            internalDependencies: new Map<string, Set<string>>()
        };

        for (const file of files.slice(0, 50)) { // Limit to avoid blocking
            try {
                const content = await vscode.workspace.fs.readFile(file);
                const text = Buffer.from(content).toString('utf-8');
                
                // Extract imports (simple regex)
                const imports = text.match(/(?:import|from|require)\s+['"`]([^'"`]+)['"`]/g) || [];
                
                imports.forEach(imp => {
                    const lib = imp.replace(/(?:import|from|require)\s+['"`]/, '').replace(/['"`].*/, '');
                    
                    if (lib.startsWith('.') || lib.startsWith('/')) {
                        // Internal dependency
                        const key = file.path;
                        if (!dependencies.internalDependencies.has(key)) {
                            dependencies.internalDependencies.set(key, new Set());
                        }
                        dependencies.internalDependencies.get(key)!.add(lib);
                    } else {
                        // External library
                        dependencies.externalLibraries.add(lib);
                    }
                    
                    dependencies.imports.set(lib, (dependencies.imports.get(lib) || 0) + 1);
                });
            } catch (error) {
                // Skip files that can't be read
            }
        }

        return {
            totalImports: Array.from(dependencies.imports.values()).reduce((a, b) => a + b, 0),
            uniqueLibraries: dependencies.externalLibraries.size,
            mostCommonImports: Array.from(dependencies.imports.entries())
                .sort((a, b) => b[1] - a[1])
                .slice(0, 10)
        };
    }

    private async _assessVerificationReadiness(files: vscode.Uri[]): Promise<any> {
        const readiness = {
            readyFiles: 0,
            needsAttention: 0,
            issues: [] as string[]
        };

        for (const file of files.slice(0, 30)) { // Limit to avoid blocking
            try {
                const content = await vscode.workspace.fs.readFile(file);
                const text = Buffer.from(content).toString('utf-8');
                
                let fileReady = true;
                
                // Check for common issues that might affect verification
                if (text.includes('eval(') || text.includes('exec(')) {
                    readiness.issues.push(`${file.path}: Uses dynamic code execution`);
                    fileReady = false;
                }
                
                if (text.length > 100000) { // Large file
                    readiness.issues.push(`${file.path}: Very large file (${Math.round(text.length/1000)}KB)`);
                    fileReady = false;
                }
                
                // Check for syntax errors (basic)
                if (file.path.endsWith('.py')) {
                    try {
                        // This is a simplified check - in reality would use Python parser
                        if (text.match(/def\s+\w+\([^)]*\)\s*:/g) === null && text.length > 100) {
                            readiness.issues.push(`${file.path}: No functions found`);
                            fileReady = false;
                        }
                    } catch (error) {
                        readiness.issues.push(`${file.path}: Syntax check failed`);
                        fileReady = false;
                    }
                }
                
                if (fileReady) {
                    readiness.readyFiles++;
                } else {
                    readiness.needsAttention++;
                }
            } catch (error) {
                readiness.issues.push(`${file.path}: Cannot read file`);
                readiness.needsAttention++;
            }
        }

        return readiness;
    }

    getCachedAnalysis(): any {
        if (!vscode.workspace.workspaceFolders) {
            return null;
        }

        const cacheKey = vscode.workspace.workspaceFolders[0].uri.toString();
        const cached = this.analysisCache.get(cacheKey);
        
        if (cached && Date.now() - cached.timestamp < this.cacheExpiryMs) {
            return cached;
        }
        
        return null;
    }
}
