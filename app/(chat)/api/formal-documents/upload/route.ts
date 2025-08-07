import { NextRequest, NextResponse } from 'next/server';
import { fileUploadHandler } from '@/lib/security/file-upload-handler';
import { getSession } from '@/db/cached-queries';
import { createClient } from '@/lib/supabase/server';
import crypto from 'crypto';

// Helper function to extract client information from request
function extractClientInfo(request: NextRequest) {
  const userAgent = request.headers.get('user-agent') || '';
  const forwarded = request.headers.get('x-forwarded-for');
  const realIP = request.headers.get('x-real-ip');
  const cfConnectingIP = request.headers.get('cf-connecting-ip');
  
  // Get IP address (prioritize CloudFlare, then real IP, then forwarded)
  const ip = cfConnectingIP || realIP || forwarded?.split(',')[0] || '127.0.0.1';
  
  // Parse User Agent for OS and browser info
  const getBrowserInfo = (ua: string) => {
    if (ua.includes('Chrome/')) return `Chrome ${ua.match(/Chrome\/([0-9.]+)/)?.[1]}`;
    if (ua.includes('Firefox/')) return `Firefox ${ua.match(/Firefox\/([0-9.]+)/)?.[1]}`;
    if (ua.includes('Safari/')) return `Safari ${ua.match(/Version\/([0-9.]+)/)?.[1]}`;
    if (ua.includes('Edge/')) return `Edge ${ua.match(/Edge\/([0-9.]+)/)?.[1]}`;
    return 'Unknown Browser';
  };
  
  const getOSInfo = (ua: string) => {
    if (ua.includes('Windows NT 10.0')) return 'Windows 10/11';
    if (ua.includes('Windows NT 6.3')) return 'Windows 8.1';
    if (ua.includes('Windows NT 6.1')) return 'Windows 7';
    if (ua.includes('Mac OS X')) return ua.match(/Mac OS X ([0-9_]+)/)?.[1]?.replace(/_/g, '.') || 'macOS';
    if (ua.includes('Linux')) return 'Linux';
    if (ua.includes('Android')) return ua.match(/Android ([0-9.]+)/)?.[1] ? `Android ${ua.match(/Android ([0-9.]+)/)?.[1]}` : 'Android';
    if (ua.includes('iPhone OS')) return ua.match(/iPhone OS ([0-9_]+)/)?.[1]?.replace(/_/g, '.') || 'iOS';
    return 'Unknown OS';
  };
  
  const getDeviceInfo = (ua: string) => {
    if (ua.includes('Mobile')) return 'Mobile Device';
    if (ua.includes('Tablet')) return 'Tablet';
    if (ua.includes('iPhone')) return 'iPhone';
    if (ua.includes('iPad')) return 'iPad';
    if (ua.includes('Android')) {
      if (ua.includes('Mobile')) return 'Android Phone';
      return 'Android Tablet';
    }
    return 'Desktop';
  };
  
  return {
    ip_address: ip,
    user_agent: userAgent,
    browser_info: getBrowserInfo(userAgent),
    os_info: getOSInfo(userAgent),
    device_info: getDeviceInfo(userAgent)
  };
}

// Async processing function for formal document uploads
async function processDocumentUploadAsync(
  sessionToken: string,
  file: File,
  documentType: 'proof_of_address' | 'proof_of_payment' | 'identification' | 'debit_order_authorisation',
  userId: string,
  chatId: string,
  submissionNotes?: string,
  metadata?: Record<string, any>
): Promise<void> {
  const supabase = await createClient();
  
  try {
    // Update session to "uploading"
    await supabase
      .from('file_upload_sessions')
      .update({
        status: 'uploading',
        progress_percentage: 10,
        current_step: 'Starting upload...'
      })
      .eq('session_token', sessionToken);

    // Update session to "validating"
    await supabase
      .from('file_upload_sessions')
      .update({
        status: 'validating',
        progress_percentage: 25,
        current_step: 'Validating file...'
      })
      .eq('session_token', sessionToken);

    // Update session to "scanning"
    await supabase
      .from('file_upload_sessions')
      .update({
        status: 'scanning',
        progress_percentage: 50,
        current_step: 'Security scanning...'
      })
      .eq('session_token', sessionToken);

    console.log(`[FormalDocAPI] Processing formal document upload: ${file.name} (${documentType})`);
    
    // Process the upload with the file upload handler
    const result = await fileUploadHandler.handleFormalDocumentUpload(
      file,
      file.name,
      documentType,
      userId,
      chatId,
      submissionNotes,
      metadata
    );

    if (result.success) {
      console.log(`[FormalDocAPI] Formal document uploaded successfully: ${result.fileId}`);
      
      // Update session to completed
      await supabase
        .from('file_upload_sessions')
        .update({
          status: 'completed',
          progress_percentage: 100,
          current_step: 'Upload completed successfully',
          metadata: {
            ...metadata,
            documentId: result.fileId,
            fileName: result.fileName,
            fileSize: result.fileSize,
            documentType,
            submissionNotes,
            status: 'pending_review',
            completedAt: new Date().toISOString()
          }
        })
        .eq('session_token', sessionToken);
    } else {
      console.error(`[FormalDocAPI] Formal document upload failed:`, result.error, result.details);
      
      // Update session to failed
      await supabase
        .from('file_upload_sessions')
        .update({
          status: 'failed',
          progress_percentage: 0,
          current_step: 'Upload failed',
          error_message: result.error || 'Upload failed',
          metadata: {
            ...metadata,
            errors: result.details || [],
            failedAt: new Date().toISOString()
          }
        })
        .eq('session_token', sessionToken);
    }
  } catch (error) {
    console.error(`[FormalDocAPI] Async processing error for session ${sessionToken}:`, error);
    
    // Update session to failed on exception
    await supabase
      .from('file_upload_sessions')
      .update({
        status: 'failed',
        progress_percentage: 0,
        current_step: 'Upload failed',
        error_message: error instanceof Error ? error.message : 'Unknown error occurred',
        metadata: {
          ...metadata,
          exception: error instanceof Error ? error.message : String(error),
          failedAt: new Date().toISOString()
        }
      })
      .eq('session_token', sessionToken);
  }
}

export async function POST(request: NextRequest) {
  try {
    // Check authentication
    const session = await getSession();
    if (!session?.id) {
      return NextResponse.json(
        { error: 'Authentication required' },
        { status: 401 }
      );
    }

    // Extract client information for security logging
    const clientInfo = extractClientInfo(request);
    
    // Parse multipart form data
    const formData = await request.formData();
    const file = formData.get('file') as File;
    const documentType = formData.get('documentType') as string;
    const chatId = formData.get('chatId') as string;
    const submissionNotes = formData.get('submissionNotes') as string | null;
    
    // Validate required fields
    if (!file) {
      return NextResponse.json(
        { error: 'No file provided' },
        { status: 400 }
      );
    }

    if (!documentType) {
      return NextResponse.json(
        { error: 'Document type is required' },
        { status: 400 }
      );
    }

    if (!chatId) {
      return NextResponse.json(
        { error: 'Chat ID is required' },
        { status: 400 }
      );
    }

    // Validate document type
    const validDocTypes = ['proof_of_address', 'proof_of_payment', 'identification', 'debit_order_authorisation'];
    if (!validDocTypes.includes(documentType)) {
      return NextResponse.json(
        { error: 'Invalid document type' },
        { status: 400 }
      );
    }

    // Validate file size (10MB max for formal documents)
    const maxSize = 10 * 1024 * 1024; // 10MB
    if (file.size > maxSize) {
      // Log security event for oversized file attempt
      await fileUploadHandler.logSecurityEvent({
        user_id: session.id,
        session_id: chatId,
        event_type: 'validation_failed',
        file_name: file.name,
        threat_details: {
          error: 'File too large',
          fileSize: file.size,
          maxSize,
          category: 'formal_document',
          uploadedAt: new Date().toISOString(),
          mimeType: file.type
        },
        // Only include valid security_logs columns
        ip_address: clientInfo.ip_address,
        user_agent: clientInfo.user_agent,
        browser_info: clientInfo.browser_info,
        os_info: clientInfo.os_info,
        device_info: clientInfo.device_info
      });

      return NextResponse.json(
        { error: 'File too large. Maximum size is 10MB for formal documents.' },
        { status: 400 }
      );
    }

    // Create upload session for progress tracking
    console.log(`[FormalDocAPI] Creating upload session for: ${file.name} (${documentType})`);
    
    const sessionToken = `formal_${Date.now()}_${Math.random().toString(36).substring(7)}`;
    
    // Create session record
    const supabase = await createClient();
    const { data: sessionData, error: sessionError } = await supabase
      .from('file_upload_sessions')
      .insert({
        user_id: session.id,
        session_token: sessionToken,
        upload_type: 'formal_document',
        document_type: documentType,
        status: 'initiated',
        progress_percentage: 0,
        current_step: 'Starting upload...',
        metadata: {
          fileName: file.name,
          fileSize: file.size,
          mimeType: file.type,
          submissionNotes,
          ...clientInfo
        }
      })
      .select()
      .single();

    if (sessionError) {
      console.error(`[FormalDocAPI] Failed to create upload session:`, sessionError);
      return NextResponse.json({
        success: false,
        error: 'Failed to create upload session',
        details: [sessionError.message]
      }, { status: 500 });
    }

    // Start async processing
    console.log(`[FormalDocAPI] Starting async processing for session: ${sessionToken}`);
    
    // Don't await - let it run asynchronously
    processDocumentUploadAsync(
      sessionToken,
      file,
      documentType as 'proof_of_address' | 'proof_of_payment' | 'identification' | 'debit_order_authorisation',
      session.id,
      chatId,
      submissionNotes || undefined,
      {
        ...clientInfo,
        uploadedAt: new Date().toISOString(),
        fileSize: file.size,
        mimeType: file.type
      }
    ).catch((error: unknown) => {
      console.error(`[FormalDocAPI] Async processing failed for session ${sessionToken}:`, error);
    });

    // Return session token immediately
    return NextResponse.json({
      success: true,
      sessionToken,
      message: 'Upload session created, processing started'
    }, { status: 200 });

  } catch (error) {
    console.error('[FormalDocAPI] Unexpected error:', error);
    
    return NextResponse.json(
      { 
        error: 'Internal server error',
        details: ['An unexpected error occurred during upload'] 
      },
      { status: 500 }
    );
  }
}

// Handle OPTIONS for CORS
export async function OPTIONS(request: NextRequest) {
  return new NextResponse(null, {
    status: 200,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    },
  });
}