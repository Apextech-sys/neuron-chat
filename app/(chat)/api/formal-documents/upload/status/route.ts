import { NextRequest, NextResponse } from 'next/server';
import { cookies } from 'next/headers';
import { createClient } from '@/lib/supabase/server';

export async function GET(request: NextRequest) {
  try {
    const supabase = await createClient();
    const { searchParams } = new URL(request.url);
    const sessionToken = searchParams.get('sessionToken');

    if (!sessionToken) {
      return NextResponse.json(
        { error: 'Session token is required' },
        { status: 400 }
      );
    }

    // Get current user session
    const { data: { user }, error: userError } = await supabase.auth.getUser();
    if (userError || !user) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    // Find upload session
    const { data: uploadSession, error: sessionError } = await supabase
      .from('file_upload_sessions')
      .select('*')
      .eq('session_token', sessionToken)
      .eq('user_id', user.id)
      .single();

    if (sessionError || !uploadSession) {
      return NextResponse.json(
        { error: 'Upload session not found' },
        { status: 404 }
      );
    }

    // Check if session has expired
    if (new Date(uploadSession.expires_at) < new Date()) {
      return NextResponse.json(
        { error: 'Upload session has expired' },
        { status: 410 }
      );
    }

    return NextResponse.json({
      session_token: uploadSession.session_token,
      status: uploadSession.status,
      progress_percentage: uploadSession.progress_percentage,
      current_step: uploadSession.current_step,
      error_message: uploadSession.error_message,
      upload_type: uploadSession.upload_type,
      document_type: uploadSession.document_type,
      metadata: uploadSession.metadata,
      created_at: uploadSession.created_at,
      updated_at: uploadSession.updated_at
    });

  } catch (error) {
    console.error('Status check error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}