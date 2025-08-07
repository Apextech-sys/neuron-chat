import { SupabaseClient } from '@supabase/supabase-js';
import { createClient } from '@/lib/supabase/server';
import { FileValidator, ValidationResult, FileInfo, ThreatType } from './file-validator';
import { Database, Tables, TablesInsert, TablesUpdate } from '@/lib/supabase/database.types';

// Use exact types from generated database schema
export type FileUploadRecord = Tables<'file_uploads'>;
export type FileUploadInsert = TablesInsert<'file_uploads'>;
export type FileUploadUpdate = TablesUpdate<'file_uploads'>;

export type FormalDocumentRecord = Tables<'formal_documents'>;
export type FormalDocumentInsert = TablesInsert<'formal_documents'>;
export type FormalDocumentUpdate = TablesUpdate<'formal_documents'>;

export type SecurityLogInsert = TablesInsert<'security_logs'>;

// Configuration interface
export interface UploadConfig {
  maxFileSize?: number;
  allowedTypes?: string[];
  enableVirusScan?: boolean;
  quarantineInfected?: boolean;
  logSecurityEvents?: boolean;
}

// Result types
export interface UploadResult {
  success: boolean;
  fileId?: string;
  fileName?: string;
  fileSize?: number;
  storageUrl?: string;
  error?: string;
  details?: string[];
}

export interface VirusScanResult {
  clean: boolean;
  threatLevel: 'none' | 'low' | 'medium' | 'high' | 'critical';
  detections: number;
  engines: number;
  threats: string[];
  scanId?: string;
}

// Main file upload handler class
export class ISPFileUploadHandler {
  private fileValidator: FileValidator;
  private config: Required<UploadConfig>;

  constructor(config?: UploadConfig) {
    this.fileValidator = new FileValidator(config?.maxFileSize);
    
    this.config = {
      maxFileSize: config?.maxFileSize || 20 * 1024 * 1024,
      allowedTypes: config?.allowedTypes || [],
      enableVirusScan: config?.enableVirusScan ?? true,
      quarantineInfected: config?.quarantineInfected ?? true,
      logSecurityEvents: config?.logSecurityEvents ?? true,
    };
  }

  private async getSupabaseClient(): Promise<SupabaseClient> {
    return await createClient();
  }

  /**
   * Handle regular file upload (generic chat attachments)
   */
  async handleFileUpload(
    file: File | Buffer,
    fileName: string,
    userId: string,
    chatId: string,
    metadata?: Record<string, any>
  ): Promise<UploadResult> {
    const startTime = Date.now();
    let fileRecord: FileUploadRecord | null = null;

    try {
      // Convert File to Buffer if needed
      let fileBuffer: Buffer;
      if (file instanceof File) {
        fileBuffer = Buffer.from(await file.arrayBuffer());
      } else {
        fileBuffer = file;
      }

      // Step 1: Validate file structure and content
      console.log(`[FileUpload] Validating file: ${fileName}`);
      const validation = await this.fileValidator.validateFile(fileBuffer, fileName);
      
      if (!validation.valid) {
        await this.logSecurityEvent({
          user_id: userId,
          session_id: chatId,
          event_type: 'validation_failed',
          file_name: fileName,
          threat_details: {
            errors: validation.errors,
            ...metadata
          },
          // Extract only the valid security_logs columns from metadata
          ip_address: metadata?.ip_address,
          user_agent: metadata?.user_agent,
          browser_info: metadata?.browser_info,
          os_info: metadata?.os_info,
          device_info: metadata?.device_info
        });

        return {
          success: false,
          error: 'File validation failed',
          details: validation.errors
        };
      }

      const fileInfo = validation.fileInfo!;

      const supabase = await this.getSupabaseClient();

      // Step 2: Check for duplicate uploads (by hash)
      const isDuplicate = await this.checkDuplicateFile(fileInfo.hash, userId, supabase);
      if (isDuplicate) {
        console.log(`[FileUpload] Duplicate file detected: ${fileInfo.hash}`);
        return {
          success: false,
          error: 'This file has already been uploaded',
          details: ['Duplicate file detected based on content hash']
        };
      }

      // Step 3: Generate unique storage path and create initial file record
      const timestamp = Date.now();
      const randomSuffix = Math.random().toString(36).substring(7);
      const uniqueFilename = `${timestamp}-${randomSuffix}-${fileInfo.sanitizedName}`;
      const storagePath = this.generateStoragePath(userId, chatId, uniqueFilename);
      
      fileRecord = await this.createFileRecord(supabase, {
        user_id: userId,
        chat_id: chatId,
        bucket_id: 'chat_attachments',
        storage_path: storagePath,
        filename: uniqueFilename,
        original_name: fileName,
        content_type: fileInfo.mime,
        size: fileInfo.size,
        url: '', // Will be updated after storage upload
        file_hash: fileInfo.hash,
        scan_status: 'pending',
        scan_date: new Date().toISOString()
      });

      if (!fileRecord?.id) {
        throw new Error('Failed to create file record');
      }

      // Step 4: Virus scanning (if enabled)
      if (this.config.enableVirusScan) {
        console.log(`[FileUpload] Scanning file for viruses: ${fileName}`);
        const scanResult = await this.scanForViruses(fileBuffer, fileName);
        
        if (!scanResult.clean) {
          await this.handleInfectedFile(
            fileRecord,
            scanResult,
            fileBuffer,
            userId,
            chatId,
            metadata
          );

          return {
            success: false,
            error: 'Security threat detected',
            details: [
              `Threat level: ${scanResult.threatLevel}`,
              `Detected by ${scanResult.detections}/${scanResult.engines} engines`,
              ...scanResult.threats
            ]
          };
        }

        // Update scan status
        await this.updateFileRecord(supabase, fileRecord.id, {
          scan_status: 'clean',
          scan_details: {
            engines: scanResult.engines,
            scanId: scanResult.scanId,
            timestamp: new Date().toISOString()
          }
        });
      }

      // Step 5: Upload to Supabase Storage
      console.log(`[FileUpload] Uploading to storage: ${storagePath}`);
      
      const { data: uploadData, error: uploadError } = await supabase.storage
        .from('chat_attachments')
        .upload(storagePath, fileBuffer, {
          contentType: fileInfo.mime,
          upsert: false,
          cacheControl: '3600'
        });

      if (uploadError) {
        throw new Error(`Storage upload failed: ${uploadError.message}`);
      }

      // Step 6: Get public URL
      const { data: urlData } = supabase.storage
        .from('chat_attachments')
        .getPublicUrl(storagePath);

      // Step 7: Update file record with storage path
      await this.updateFileRecord(supabase, fileRecord.id, {
        storage_path: storagePath,
        url: urlData.publicUrl,
        scan_status: 'clean'
      });

      const elapsedTime = Date.now() - startTime;
      console.log(`[FileUpload] Upload completed in ${elapsedTime}ms`);

      return {
        success: true,
        fileId: fileRecord.id,
        fileName: fileInfo.sanitizedName,
        fileSize: fileInfo.size,
        storageUrl: urlData.publicUrl
      };

    } catch (error) {
      console.error('[FileUpload] Error:', error);
      
      // Clean up on error
      if (fileRecord?.id) {
        const supabase = await this.getSupabaseClient();
        await this.updateFileRecord(supabase, fileRecord.id, {
          scan_status: 'error',
          deleted_at: new Date().toISOString()
        });
      }

      return {
        success: false,
        error: 'Upload failed',
        details: [error instanceof Error ? error.message : 'Unknown error']
      };
    }
  }

  /**
   * Handle formal document upload (ISP documents)
   */
  async handleFormalDocumentUpload(
    file: File | Buffer,
    fileName: string,
    documentType: 'proof_of_address' | 'proof_of_payment' | 'identification' | 'debit_order_authorisation',
    userId: string,
    chatId: string,
    submissionNotes?: string,
    metadata?: Record<string, any>
  ): Promise<UploadResult> {
    const startTime = Date.now();
    let fileRecord: FileUploadRecord | null = null;
    let formalDocRecord: FormalDocumentRecord | null = null;

    try {
      // Convert File to Buffer if needed
      let fileBuffer: Buffer;
      if (file instanceof File) {
        fileBuffer = Buffer.from(await file.arrayBuffer());
      } else {
        fileBuffer = file;
      }

      // Step 1: Enhanced validation for formal documents (stricter)
      console.log(`[FormalDoc] Validating formal document: ${fileName} (${documentType})`);
      const validation = await this.fileValidator.validateFile(fileBuffer, fileName, true);
      
      if (!validation.valid) {
        await this.logSecurityEvent({
          user_id: userId,
          session_id: chatId,
          event_type: 'validation_failed',
          file_name: fileName,
          threat_details: {
            errors: validation.errors,
            documentType,
            category: 'formal_document',
            ...metadata
          },
          // Extract only the valid security_logs columns from metadata
          ip_address: metadata?.ip_address,
          user_agent: metadata?.user_agent,
          browser_info: metadata?.browser_info,
          os_info: metadata?.os_info,
          device_info: metadata?.device_info
        });

        return {
          success: false,
          error: 'Formal document validation failed',
          details: validation.errors
        };
      }

      const fileInfo = validation.fileInfo!;

      const supabase = await this.getSupabaseClient();

      // Step 2: Generate unique storage path and create file upload record
      const timestamp = Date.now();
      const randomSuffix = Math.random().toString(36).substring(7);
      const uniqueFilename = `${timestamp}-${randomSuffix}-${fileInfo.sanitizedName}`;
      const storagePath = this.generateFormalDocStoragePath(userId, documentType, uniqueFilename);
      
      fileRecord = await this.createFileRecord(supabase, {
        user_id: userId,
        chat_id: chatId,
        bucket_id: 'formal-documents',
        storage_path: storagePath,
        filename: uniqueFilename,
        original_name: fileName,
        content_type: fileInfo.mime,
        size: fileInfo.size,
        url: '', // Will be updated after storage upload
        file_hash: fileInfo.hash,
        scan_status: 'pending',
        scan_date: new Date().toISOString()
      });

      if (!fileRecord?.id) {
        throw new Error('Failed to create file record');
      }

      // Step 3: Enhanced virus scanning for formal documents
      if (this.config.enableVirusScan) {
        console.log(`[FormalDoc] Enhanced scanning for formal document: ${fileName}`);
        const scanResult = await this.scanForViruses(fileBuffer, fileName);
        
        if (!scanResult.clean) {
          await this.handleInfectedFile(
            fileRecord,
            scanResult,
            fileBuffer,
            userId,
            chatId,
            { ...metadata, documentType, category: 'formal_document' }
          );

          return {
            success: false,
            error: 'Security threat detected in formal document',
            details: [
              `Threat level: ${scanResult.threatLevel}`,
              `Detected by ${scanResult.detections}/${scanResult.engines} engines`,
              ...scanResult.threats
            ]
          };
        }

        // Update scan status
        await this.updateFileRecord(supabase, fileRecord.id, {
          scan_status: 'clean',
          scan_details: {
            engines: scanResult.engines,
            scanId: scanResult.scanId,
            timestamp: new Date().toISOString(),
            documentType
          }
        });
      }

      // Step 4: Upload to secure formal documents storage
      console.log(`[FormalDoc] Uploading to secure storage: ${storagePath}`);
      
      const { data: uploadData, error: uploadError } = await supabase.storage
        .from('formal-documents')
        .upload(storagePath, fileBuffer, {
          contentType: fileInfo.mime,
          upsert: false,
          cacheControl: 'private, max-age=0' // No caching for sensitive docs
        });

      if (uploadError) {
        throw new Error(`Formal document storage upload failed: ${uploadError.message}`);
      }

      // Step 5: Get secure URL (private - requires authentication)
      const { data: urlData } = await supabase.storage
        .from('formal-documents')
        .createSignedUrl(storagePath, 3600); // 1 hour expiry

      // Step 6: Update file record with storage path
      await this.updateFileRecord(supabase, fileRecord.id, {
        storage_path: storagePath,
        url: urlData?.signedUrl || '',
        scan_status: 'clean'
      });

      // Step 7: Create formal document record (without validation_status - that's in document_validations table)
      formalDocRecord = await this.createFormalDocumentRecord(supabase, {
        title: `${documentType} - ${fileInfo.sanitizedName}`,
        document_type: documentType,
        file_reference_id: fileRecord.id,
        submission_notes: submissionNotes,
        user_id: userId,
        scan_status: 'clean',
        scan_details: {
          fileHash: fileInfo.hash,
          originalSize: fileInfo.size,
          mimeType: fileInfo.mime,
          scanTimestamp: new Date().toISOString()
        }
      });

      if (!formalDocRecord?.id) {
        throw new Error('Failed to create formal document record');
      }

      const elapsedTime = Date.now() - startTime;
      console.log(`[FormalDoc] Formal document upload completed in ${elapsedTime}ms`);

      return {
        success: true,
        fileId: formalDocRecord.id,
        fileName: fileInfo.sanitizedName,
        fileSize: fileInfo.size,
        storageUrl: urlData?.signedUrl
      };

    } catch (error) {
      console.error('[FormalDoc] Error:', error);
      
      // Clean up on error
      if (fileRecord?.id) {
        const supabase = await this.getSupabaseClient();
        await this.updateFileRecord(supabase, fileRecord.id, {
          scan_status: 'error',
          deleted_at: new Date().toISOString()
        });
      }

      return {
        success: false,
        error: 'Formal document upload failed',
        details: [error instanceof Error ? error.message : 'Unknown error']
      };
    }
  }

  /**
   * Scan file for viruses using VirusTotal or ClamAV
   */
  private async scanForViruses(
    fileBuffer: Buffer,
    fileName: string
  ): Promise<VirusScanResult> {
    // This is where you'd integrate with VirusTotal API or ClamAV
    // For now, returning a mock implementation
    
    // Example with VirusTotal (you'd need to implement the actual API calls)
    if (process.env.VIRUSTOTAL_API_KEY) {
      return await this.scanWithVirusTotal(fileBuffer, fileName);
    }
    
    // Fallback to basic pattern detection from validator
    const validation = await this.fileValidator.validateFile(fileBuffer, fileName, true);
    
    if (!validation.valid) {
      return {
        clean: false,
        threatLevel: 'high',
        detections: validation.errors.length,
        engines: 1,
        threats: validation.errors
      };
    }

    return {
      clean: true,
      threatLevel: 'none',
      detections: 0,
      engines: 1,
      threats: []
    };
  }

  /**
   * VirusTotal integration (placeholder - implement actual API calls)
   */
  private async scanWithVirusTotal(
    fileBuffer: Buffer,
    fileName: string
  ): Promise<VirusScanResult> {
    // Implement actual VirusTotal API integration here
    // This is a placeholder that shows the structure
    
    const apiKey = process.env.VIRUSTOTAL_API_KEY;
    if (!apiKey) {
      throw new Error('VirusTotal API key not configured');
    }

    // TODO: Implement actual VirusTotal API calls
    // 1. Upload file to VirusTotal
    // 2. Poll for results
    // 3. Parse and return scan results

    // Mock response for now
    return {
      clean: true,
      threatLevel: 'none',
      detections: 0,
      engines: 70,
      threats: [],
      scanId: 'mock-scan-id'
    };
  }

  /**
   * Handle infected file (quarantine or delete)
   */
  private async handleInfectedFile(
    fileRecord: FileUploadRecord,
    scanResult: VirusScanResult,
    fileBuffer: Buffer,
    userId: string,
    sessionId: string,
    metadata?: Record<string, any>
  ): Promise<void> {
    // Log security event
    await this.logSecurityEvent({
      user_id: userId,
      session_id: sessionId,
      event_type: 'malware_detected',
      file_name: fileRecord.filename,
      file_hash: fileRecord.file_hash,
      threat_details: {
        threatLevel: scanResult.threatLevel,
        detections: scanResult.detections,
        threats: scanResult.threats,
        ...metadata
      },
      // Extract only the valid security_logs columns from metadata
      ip_address: metadata?.ip_address,
      user_agent: metadata?.user_agent,
      browser_info: metadata?.browser_info,
      os_info: metadata?.os_info,
      device_info: metadata?.device_info
    });

    const supabase = await this.getSupabaseClient();
    
    // Update file record
    await this.updateFileRecord(supabase, fileRecord.id!, {
      scan_status: 'infected',
      scan_details: scanResult as any,
      deleted_at: new Date().toISOString()
    });

    // Optionally quarantine the file
    if (this.config.quarantineInfected) {
      const quarantinePath = `quarantine/${userId}/${fileRecord.file_hash}`;
      await supabase.storage
        .from('quarantine')
        .upload(quarantinePath, fileBuffer, {
          contentType: 'application/octet-stream',
          upsert: false
        });
    }
  }

  /**
   * Check if file already exists
   */
  private async checkDuplicateFile(
    fileHash: string,
    userId: string,
    supabase: SupabaseClient
  ): Promise<boolean> {
    const { data, error } = await supabase
      .from('file_uploads')
      .select('id')
      .eq('file_hash', fileHash)
      .eq('user_id', userId)
      .is('deleted_at', null)
      .single();

    return !!data && !error;
  }

  /**
   * Create file upload record
   */
  private async createFileRecord(
    supabase: SupabaseClient,
    record: FileUploadInsert
  ): Promise<FileUploadRecord | null> {
    const { data, error } = await supabase
      .from('file_uploads')
      .insert(record)
      .select()
      .single();

    if (error) {
      console.error('[FileUpload] Failed to create record:', error);
      return null;
    }

    return data;
  }

  /**
   * Create formal document record
   */
  private async createFormalDocumentRecord(
    supabase: SupabaseClient,
    record: FormalDocumentInsert
  ): Promise<FormalDocumentRecord | null> {
    const { data, error } = await supabase
      .from('formal_documents')
      .insert(record)
      .select()
      .single();

    if (error) {
      console.error('[FormalDoc] Failed to create record:', error);
      return null;
    }

    return data;
  }

  /**
   * Update file upload record
   */
  private async updateFileRecord(
    supabase: SupabaseClient,
    id: string,
    updates: FileUploadUpdate
  ): Promise<void> {
    const { error } = await supabase
      .from('file_uploads')
      .update(updates)
      .eq('id', id);

    if (error) {
      console.error('[FileUpload] Failed to update record:', error);
    }
  }

  /**
   * Log security event
   */
  async logSecurityEvent(log: SecurityLogInsert): Promise<void> {
    if (!this.config.logSecurityEvents) {
      return;
    }

    const supabase = await this.getSupabaseClient();
    const { error } = await supabase
      .from('security_logs')
      .insert(log);

    if (error) {
      console.error('[Security] Failed to log security event:', error);
    }
  }

  /**
   * Generate storage path for regular files
   */
  private generateStoragePath(
    userId: string,
    chatId: string,
    fileName: string
  ): string {
    return `${userId}/${chatId}/${fileName}`;
  }

  /**
   * Generate storage path for formal documents
   */
  private generateFormalDocStoragePath(
    userId: string,
    documentType: string,
    fileName: string
  ): string {
    return `${userId}/formal/${documentType}/${fileName}`;
  }

  /**
   * Delete file from storage and mark as deleted
   */
  async deleteFile(fileId: string, userId: string): Promise<boolean> {
    try {
      const supabase = await this.getSupabaseClient();
      
      // Get file record
      const { data: fileRecord, error: fetchError } = await supabase
        .from('file_uploads')
        .select('*')
        .eq('id', fileId)
        .eq('user_id', userId)
        .single();

      if (fetchError || !fileRecord) {
        return false;
      }

      // Delete from storage
      if (fileRecord.storage_path) {
        await supabase.storage
          .from('chat_attachments')
          .remove([fileRecord.storage_path]);
      }

      // Mark as deleted in database
      await this.updateFileRecord(supabase, fileId, {
        deleted_at: new Date().toISOString()
      });

      return true;
    } catch (error) {
      console.error('[FileUpload] Delete failed:', error);
      return false;
    }
  }

  /**
   * Get user's uploaded files
   */
  async getUserFiles(
    userId: string,
    limit: number = 10,
    offset: number = 0
  ): Promise<FileUploadRecord[]> {
    const supabase = await this.getSupabaseClient();
    const { data, error } = await supabase
      .from('file_uploads')
      .select('*')
      .eq('user_id', userId)
      .is('deleted_at', null)
      .order('created_at', { ascending: false })
      .range(offset, offset + limit - 1);

    if (error) {
      console.error('[FileUpload] Failed to fetch user files:', error);
      return [];
    }

    return data || [];
  }
}

// Export singleton instance with default configuration
export const fileUploadHandler = new ISPFileUploadHandler({
  maxFileSize: 20 * 1024 * 1024, // 20MB
  enableVirusScan: true,
  quarantineInfected: true,
  logSecurityEvents: true
});

// Express/Fastify route handler example
export async function handleFileUploadRoute(req: any, res: any) {
  const { file } = req;
  const { userId, chatId } = req.user; // Assuming auth middleware sets this

  if (!file) {
    return res.status(400).json({ error: 'No file provided' });
  }

  const result = await fileUploadHandler.handleFileUpload(
    file.buffer,
    file.originalname,
    userId,
    chatId
  );

  if (result.success) {
    return res.status(200).json(result);
  } else {
    return res.status(400).json(result);
  }
}