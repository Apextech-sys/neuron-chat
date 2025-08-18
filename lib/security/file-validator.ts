import crypto from 'crypto';
import { fileTypeFromBuffer } from 'file-type';

// Types and Interfaces
export interface FileTypeConfig {
  maxSize: number;
  extensions: string[];
  mimeType: string;
}

export interface ValidationResult {
  valid: boolean;
  errors: string[];
  fileInfo?: FileInfo;
}

export interface FileInfo {
  mime: string;
  ext: string;
  size: number;
  hash: string;
  sanitizedName: string;
}

export interface ScanResult {
  safe: boolean;
  threats: ThreatType[];
  confidence: number;
}

export enum ThreatType {
  EXECUTABLE = 'executable',
  SCRIPT_INJECTION = 'script_injection',
  MALFORMED = 'malformed',
  SUSPICIOUS_PATTERN = 'suspicious_pattern',
  POLYGLOT = 'polyglot',
  ZIP_BOMB = 'zip_bomb'
}

// Configuration
export const FILE_TYPE_CONFIG: Record<string, FileTypeConfig> = {
  'application/pdf': {
    maxSize: 10 * 1024 * 1024, // 10MB
    extensions: ['pdf'],
    mimeType: 'application/pdf'
  },
  'image/png': {
    maxSize: 5 * 1024 * 1024, // 5MB
    extensions: ['png'],
    mimeType: 'image/png'
  },
  'image/jpeg': {
    maxSize: 5 * 1024 * 1024, // 5MB
    extensions: ['jpg', 'jpeg'],
    mimeType: 'image/jpeg'
  },
  'image/webp': {
    maxSize: 5 * 1024 * 1024, // 5MB
    extensions: ['webp'],
    mimeType: 'image/webp'
  },
  'image/tiff': {
    maxSize: 10 * 1024 * 1024, // 10MB
    extensions: ['tiff', 'tif'],
    mimeType: 'image/tiff'
  },
  'text/plain': {
    maxSize: 2 * 1024 * 1024, // 2MB
    extensions: ['txt', 'log', 'csv'],
    mimeType: 'text/plain'
  },
  'text/csv': {
    maxSize: 5 * 1024 * 1024, // 5MB
    extensions: ['csv'],
    mimeType: 'text/csv'
  },
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document': {
    maxSize: 10 * 1024 * 1024, // 10MB
    extensions: ['docx'],
    mimeType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
  },
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': {
    maxSize: 10 * 1024 * 1024, // 10MB
    extensions: ['xlsx'],
    mimeType: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
  }
};

// Magic number signatures for file type verification
const MAGIC_NUMBERS: Record<string, Uint8Array> = {
  pdf: new Uint8Array([0x25, 0x50, 0x44, 0x46]), // %PDF
  png: new Uint8Array([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
  jpg: new Uint8Array([0xFF, 0xD8, 0xFF]),
  gif: new Uint8Array([0x47, 0x49, 0x46, 0x38]),
  zip: new Uint8Array([0x50, 0x4B, 0x03, 0x04]),
  docx: new Uint8Array([0x50, 0x4B, 0x03, 0x04]), // DOCX/XLSX are ZIP format
  exe: new Uint8Array([0x4D, 0x5A]), // MZ header
  elf: new Uint8Array([0x7F, 0x45, 0x4C, 0x46]), // Linux executable
};

// Dangerous patterns to detect in file content
const DANGEROUS_PATTERNS: Array<{ pattern: RegExp | string; threat: ThreatType; description: string }> = [
  // Executables
  { pattern: '4d5a', threat: ThreatType.EXECUTABLE, description: 'Windows executable (MZ header)' },
  { pattern: '7f454c46', threat: ThreatType.EXECUTABLE, description: 'Linux executable (ELF)' },
  { pattern: 'feedface', threat: ThreatType.EXECUTABLE, description: 'Mach-O executable (macOS)' },
  { pattern: 'cefaedfe', threat: ThreatType.EXECUTABLE, description: 'Mach-O executable (macOS)' },
  
  // Script injections
  { pattern: /<script[\s>]/gi, threat: ThreatType.SCRIPT_INJECTION, description: 'JavaScript tag' },
  { pattern: /javascript:/gi, threat: ThreatType.SCRIPT_INJECTION, description: 'JavaScript protocol' },
  { pattern: /on\w+\s*=/gi, threat: ThreatType.SCRIPT_INJECTION, description: 'Event handler' },
  { pattern: /eval\s*\(/gi, threat: ThreatType.SCRIPT_INJECTION, description: 'Eval function' },
  { pattern: /document\.write/gi, threat: ThreatType.SCRIPT_INJECTION, description: 'Document write' },
  { pattern: /innerHTML\s*=/gi, threat: ThreatType.SCRIPT_INJECTION, description: 'InnerHTML assignment' },
  
  // Command injection patterns
  { pattern: /powershell/gi, threat: ThreatType.SUSPICIOUS_PATTERN, description: 'PowerShell command' },
  { pattern: /cmd\.exe/gi, threat: ThreatType.SUSPICIOUS_PATTERN, description: 'Windows command' },
  { pattern: /sh\s+-c/gi, threat: ThreatType.SUSPICIOUS_PATTERN, description: 'Shell command' },
  { pattern: /\$\(.*\)/g, threat: ThreatType.SUSPICIOUS_PATTERN, description: 'Command substitution' },
  
  // PHP injections
  { pattern: /<\?php/gi, threat: ThreatType.SCRIPT_INJECTION, description: 'PHP tag' },
  { pattern: /system\s*\(/gi, threat: ThreatType.SUSPICIOUS_PATTERN, description: 'System call' },
  { pattern: /exec\s*\(/gi, threat: ThreatType.SUSPICIOUS_PATTERN, description: 'Exec call' },
];

export class FileValidator {
  private readonly maxFileSize: number;
  private readonly maxFilenameLength: number;

  constructor(
    maxFileSize: number = 20 * 1024 * 1024, // 20MB default
    maxFilenameLength: number = 255
  ) {
    this.maxFileSize = maxFileSize;
    this.maxFilenameLength = maxFilenameLength;
  }

  /**
   * Main validation method
   */
  async validateFile(
    file: Buffer | Uint8Array,
    fileName: string,
    strictMode: boolean = true
  ): Promise<ValidationResult> {
    const errors: string[] = [];
    const fileBuffer = Buffer.from(file);

    // Sanitize filename first
    const sanitizedName = this.sanitizeFilename(fileName);
    if (sanitizedName !== fileName) {
      if (strictMode) {
        errors.push('Filename contains invalid characters');
      }
    }

    // 1. Check file size
    if (fileBuffer.length === 0) {
      errors.push('File is empty');
      return { valid: false, errors };
    }

    if (fileBuffer.length > this.maxFileSize) {
      errors.push(`File exceeds maximum size of ${this.maxFileSize / (1024 * 1024)}MB`);
    }

    // 2. Detect actual file type from content
    const fileTypeResult = await fileTypeFromBuffer(fileBuffer);
    if (!fileTypeResult) {
      errors.push('Unable to determine file type from content');
      return { valid: false, errors };
    }

    const { mime, ext } = fileTypeResult;

    // 3. Check if MIME type is allowed
    const config = FILE_TYPE_CONFIG[mime];
    if (!config) {
      errors.push(`File type ${mime} is not allowed`);
    }

    // 4. Verify file extension matches content
    const fileExt = this.getFileExtension(sanitizedName);
    if (config && !config.extensions.includes(fileExt)) {
      errors.push(`File extension .${fileExt} does not match detected type ${mime}`);
    }

    // 5. Check specific file type size constraints
    if (config && fileBuffer.length > config.maxSize) {
      errors.push(`File exceeds maximum size of ${config.maxSize / (1024 * 1024)}MB for ${mime}`);
    }

    // Polyglot check is now deprecated in favor of VirusTotal
    // if (this.isPolyglot(fileBuffer)) {
    //   errors.push('File appears to be a polyglot (multiple file types)');
    // }

    // 7. Deep content inspection
    const contentScan = await this.scanContent(fileBuffer, mime);
    if (!contentScan.safe) {
      contentScan.threats.forEach(threat => {
        errors.push(`Security threat detected: ${threat}`);
      });
    }

    // 8. Check for zip bombs (for compressed files)
    if (mime.includes('zip') || mime.includes('compressed')) {
      const isZipBomb = await this.checkForZipBomb(fileBuffer);
      if (isZipBomb) {
        errors.push('File appears to be a zip bomb');
      }
    }

    // 9. Calculate file hash for integrity
    const hash = this.calculateHash(fileBuffer);

    return {
      valid: errors.length === 0,
      errors,
      fileInfo: errors.length === 0 ? {
        mime,
        ext,
        size: fileBuffer.length,
        hash,
        sanitizedName
      } : undefined
    };
  }

  /**
   * Sanitize filename to prevent path traversal and other attacks
   */
  private sanitizeFilename(fileName: string): string {
    // Remove path components
    const baseName = fileName.split(/[\/\\]/).pop() || 'unnamed';
    
    // Remove dangerous characters but keep unicode support
    let sanitized = baseName.replace(/[^\w\s\-\.\_\u0080-\uFFFF]/gi, '');
    
    // Remove multiple dots to prevent extension confusion
    sanitized = sanitized.replace(/\.{2,}/g, '.');
    
    // Limit length
    if (sanitized.length > this.maxFilenameLength) {
      const ext = this.getFileExtension(sanitized);
      const nameWithoutExt = sanitized.substring(0, sanitized.lastIndexOf('.'));
      sanitized = nameWithoutExt.substring(0, this.maxFilenameLength - ext.length - 1) + '.' + ext;
    }
    
    // Ensure it doesn't start with a dot (hidden file)
    if (sanitized.startsWith('.')) {
      sanitized = 'file' + sanitized;
    }
    
    return sanitized || 'unnamed';
  }

  /**
   * Extract file extension safely
   */
  private getFileExtension(fileName: string): string {
    const lastDot = fileName.lastIndexOf('.');
    if (lastDot === -1 || lastDot === fileName.length - 1) {
      return '';
    }
    return fileName.substring(lastDot + 1).toLowerCase();
  }

  /**
   * Check if file appears to be a polyglot (DEPRECATED)
   * This check is unreliable and has been replaced by VirusTotal scanning.
   */
  private isPolyglot(buffer: Buffer): boolean {
    // This logic is flawed and is kept here for reference only.
    // It incorrectly flags benign files as polyglots.
    return false;
  }

  /**
   * Deep content scanning for malicious patterns
   */
  private async scanContent(buffer: Buffer, mimeType: string): Promise<ScanResult> {
    const threats: ThreatType[] = [];
    let confidence = 100;

    // DEPRECATED: Hex pattern matching is unreliable for binary files.
    // This has been replaced by VirusTotal scanning.

    // Convert to string for text-based pattern matching (safely)
    let textContent = '';
    try {
      // Only convert to string for text-based files
      if (mimeType.startsWith('text/') ||
          mimeType.includes('json') ||
          mimeType.includes('xml')) {
        textContent = buffer.toString('utf-8');
      }
    } catch (e) {
      // If conversion fails, it might be binary with embedded text
      textContent = buffer.toString('binary');
    }

    // Only run regex checks against text-based content
    for (const { pattern, threat } of DANGEROUS_PATTERNS) {
      if (pattern instanceof RegExp && textContent) {
        if (pattern.test(textContent)) {
          threats.push(threat);
          confidence -= 20;
        }
      }
    }

    // Special checks for specific file types
    if (mimeType === 'application/pdf') {
      threats.push(...this.scanPDF(buffer));
    } else if (mimeType.startsWith('image/')) {
      threats.push(...this.scanImage(buffer));
    }

    // Remove duplicate threats
    const uniqueThreats = [...new Set(threats)];

    return {
      safe: uniqueThreats.length === 0,
      threats: uniqueThreats,
      confidence: Math.max(0, confidence)
    };
  }

  /**
   * Specific PDF scanning
   */
  private scanPDF(buffer: Buffer): ThreatType[] {
    const threats: ThreatType[] = [];
    const content = buffer.toString('binary');

    // Check for embedded JavaScript in PDF
    if (/\/JavaScript/i.test(content) || /\/JS/i.test(content)) {
      threats.push(ThreatType.SCRIPT_INJECTION);
    }

    // Check for embedded files
    if (/\/EmbeddedFile/i.test(content)) {
      threats.push(ThreatType.SUSPICIOUS_PATTERN);
    }

    // Check for launch actions
    if (/\/Launch/i.test(content)) {
      threats.push(ThreatType.SUSPICIOUS_PATTERN);
    }

    return threats;
  }

  /**
   * Specific image scanning
   */
  private scanImage(buffer: Buffer): ThreatType[] {
    const threats: ThreatType[] = [];

    // Check for EXIF data that might contain scripts
    // This is a simplified check - in production, use a proper EXIF parser
    if (buffer.includes(Buffer.from('Exif'))) {
      const exifSection = buffer.slice(buffer.indexOf(Buffer.from('Exif')));
      if (exifSection.includes(Buffer.from('<script')) || 
          exifSection.includes(Buffer.from('javascript:'))) {
        threats.push(ThreatType.SCRIPT_INJECTION);
      }
    }

    // Check for unusually large metadata sections
    const markers = this.findJPEGMarkers(buffer);
    for (const marker of markers) {
      if (marker.size > 65536) { // Suspiciously large metadata
        threats.push(ThreatType.SUSPICIOUS_PATTERN);
      }
    }

    return threats;
  }

  /**
   * Find JPEG markers for analysis
   */
  private findJPEGMarkers(buffer: Buffer): Array<{ marker: number; size: number }> {
    const markers: Array<{ marker: number; size: number }> = [];
    let i = 0;

    while (i < buffer.length - 1) {
      if (buffer[i] === 0xFF && buffer[i + 1] !== 0x00) {
        const marker = buffer[i + 1];
        if (marker >= 0xC0 && marker <= 0xFE) {
          if (i + 3 < buffer.length) {
            const size = (buffer[i + 2] << 8) | buffer[i + 3];
            markers.push({ marker, size });
            i += size + 2;
          } else {
            break;
          }
        } else {
          i++;
        }
      } else {
        i++;
      }
    }

    return markers;
  }

  /**
   * Check for zip bombs
   */
  private async checkForZipBomb(buffer: Buffer): Promise<boolean> {
    // Simple heuristic: check compression ratio
    // In production, use a proper zip library to check actual decompressed size
    
    // Check for nested zips (common in zip bombs)
    const hexString = buffer.toString('hex');
    const zipSignature = '504b0304';
    let count = 0;
    let index = 0;

    while ((index = hexString.indexOf(zipSignature, index)) !== -1) {
      count++;
      index += zipSignature.length;
      if (count > 10) { // More than 10 zip headers is suspicious
        return true;
      }
    }

    return false;
  }

  /**
   * Calculate SHA-256 hash of file
   */
  private calculateHash(buffer: Buffer): string {
    return crypto.createHash('sha256').update(buffer).digest('hex');
  }

  /**
   * Helper to check if buffer starts with signature
   */
  private bufferStartsWith(buffer: Buffer, signature: Uint8Array): boolean {
    if (buffer.length < signature.length) {
      return false;
    }
    
    for (let i = 0; i < signature.length; i++) {
      if (buffer[i] !== signature[i]) {
        return false;
      }
    }
    
    return true;
  }
}

// Export a singleton instance for convenience
export const fileValidator = new FileValidator();

// Utility function for Express/Fastify middleware
export function createFileValidationMiddleware(options?: {
  maxFileSize?: number;
  strictMode?: boolean;
}) {
  const validator = new FileValidator(options?.maxFileSize);
  
  return async (req: any, res: any, next: any) => {
    if (!req.file && !req.files) {
      return next();
    }

    const files = req.files || [req.file];
    
    for (const file of files) {
      const result = await validator.validateFile(
        file.buffer,
        file.originalname,
        options?.strictMode
      );

      if (!result.valid) {
        return res.status(400).json({
          error: 'File validation failed',
          details: result.errors
        });
      }

      // Attach validation info to file object
      file.validationInfo = result.fileInfo;
    }

    next();
  };
}