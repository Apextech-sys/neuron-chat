-- Add security logging and enhanced file tracking capabilities
-- This migration adds new tables and columns for comprehensive security monitoring

-- Create security_logs table for detailed security event tracking
CREATE TABLE IF NOT EXISTS public.security_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    session_id TEXT, -- Can be chat_id or other session identifier
    event_type TEXT NOT NULL CHECK (event_type IN (
        'malware_detected',
        'validation_failed', 
        'upload_blocked',
        'file_quarantined',
        'suspicious_activity',
        'unauthorized_access',
        'rate_limit_exceeded'
    )),
    file_name TEXT,
    file_hash TEXT,
    threat_details JSONB,
    
    -- Network and client information
    ip_address INET,
    user_agent TEXT,
    os_info TEXT,
    browser_info TEXT,
    device_info TEXT,
    country_code TEXT,
    city TEXT,
    
    -- Additional security context
    severity_level TEXT DEFAULT 'medium' CHECK (severity_level IN ('low', 'medium', 'high', 'critical')),
    resolved BOOLEAN DEFAULT false,
    resolution_notes TEXT,
    resolved_at TIMESTAMP WITH TIME ZONE,
    resolved_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT TIMEZONE('utc', NOW()) NOT NULL
);

-- Add enhanced columns to file_uploads table
ALTER TABLE public.file_uploads 
ADD COLUMN IF NOT EXISTS scan_status TEXT DEFAULT 'pending' CHECK (scan_status IN ('pending', 'clean', 'infected', 'error')),
ADD COLUMN IF NOT EXISTS scan_date TIMESTAMP WITH TIME ZONE DEFAULT TIMEZONE('utc', NOW()),
ADD COLUMN IF NOT EXISTS scan_details JSONB,
ADD COLUMN IF NOT EXISTS virustotal_id TEXT,
ADD COLUMN IF NOT EXISTS file_hash TEXT,
ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE DEFAULT TIMEZONE('utc', NOW()),
ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP WITH TIME ZONE;

-- Add enhanced columns to formal_documents table  
ALTER TABLE public.formal_documents
ADD COLUMN IF NOT EXISTS scan_status TEXT DEFAULT 'pending' CHECK (scan_status IN ('pending', 'clean', 'infected', 'error')),
ADD COLUMN IF NOT EXISTS scan_details JSONB,
ADD COLUMN IF NOT EXISTS validation_notes TEXT,
ADD COLUMN IF NOT EXISTS reviewed_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
ADD COLUMN IF NOT EXISTS priority_level TEXT DEFAULT 'normal' CHECK (priority_level IN ('low', 'normal', 'high', 'urgent'));

-- Create quarantine storage table for infected files
CREATE TABLE IF NOT EXISTS public.quarantined_files (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    original_file_id UUID REFERENCES public.file_uploads(id) ON DELETE CASCADE,
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    file_name TEXT NOT NULL,
    file_hash TEXT NOT NULL,
    quarantine_path TEXT NOT NULL,
    threat_level TEXT NOT NULL CHECK (threat_level IN ('low', 'medium', 'high', 'critical')),
    threat_details JSONB,
    quarantined_at TIMESTAMP WITH TIME ZONE DEFAULT TIMEZONE('utc', NOW()) NOT NULL,
    auto_delete_at TIMESTAMP WITH TIME ZONE DEFAULT (TIMEZONE('utc', NOW()) + INTERVAL '30 days'), -- Auto-delete after 30 days
    manually_reviewed BOOLEAN DEFAULT false,
    review_notes TEXT,
    reviewed_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    reviewed_at TIMESTAMP WITH TIME ZONE
);

-- Create file upload sessions table for tracking upload progress
CREATE TABLE IF NOT EXISTS public.file_upload_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    session_token TEXT UNIQUE NOT NULL,
    upload_type TEXT NOT NULL CHECK (upload_type IN ('generic', 'formal_document')),
    document_type TEXT CHECK (document_type IN ('proof_of_address', 'proof_of_payment', 'identification', 'debit_order_authorisation')),
    status TEXT DEFAULT 'initiated' CHECK (status IN ('initiated', 'uploading', 'validating', 'scanning', 'completed', 'failed', 'cancelled')),
    progress_percentage INTEGER DEFAULT 0 CHECK (progress_percentage >= 0 AND progress_percentage <= 100),
    current_step TEXT,
    error_message TEXT,
    metadata JSONB,
    expires_at TIMESTAMP WITH TIME ZONE DEFAULT (TIMEZONE('utc', NOW()) + INTERVAL '1 hour'),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT TIMEZONE('utc', NOW()) NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT TIMEZONE('utc', NOW()) NOT NULL
);

-- Enable Row Level Security
ALTER TABLE public.security_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.quarantined_files ENABLE ROW LEVEL SECURITY;  
ALTER TABLE public.file_upload_sessions ENABLE ROW LEVEL SECURITY;

-- Create RLS policies for security_logs
CREATE POLICY "Users can view own security logs"
ON public.security_logs FOR SELECT
USING (auth.uid() = user_id);

-- Admin/staff can view all security logs (create role later)
-- CREATE POLICY "Staff can view all security logs"  
-- ON public.security_logs FOR SELECT
-- USING (EXISTS (SELECT 1 FROM auth.users WHERE id = auth.uid() AND role = 'staff'));

CREATE POLICY "System can insert security logs"
ON public.security_logs FOR INSERT
WITH CHECK (true); -- Allow system to log all security events

-- Create RLS policies for quarantined_files
CREATE POLICY "Users cannot view quarantined files"
ON public.quarantined_files FOR SELECT
USING (false); -- Only admins should access quarantined files

-- CREATE POLICY "Staff can view quarantined files"
-- ON public.quarantined_files FOR ALL
-- USING (EXISTS (SELECT 1 FROM auth.users WHERE id = auth.uid() AND role = 'staff'));

-- Create RLS policies for file_upload_sessions  
CREATE POLICY "Users can manage own upload sessions"
ON public.file_upload_sessions FOR ALL
USING (auth.uid() = user_id);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_security_logs_user_id ON public.security_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_security_logs_event_type ON public.security_logs(event_type);
CREATE INDEX IF NOT EXISTS idx_security_logs_severity ON public.security_logs(severity_level);
CREATE INDEX IF NOT EXISTS idx_security_logs_created_at ON public.security_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_security_logs_ip_address ON public.security_logs(ip_address);
CREATE INDEX IF NOT EXISTS idx_security_logs_resolved ON public.security_logs(resolved) WHERE NOT resolved;

CREATE INDEX IF NOT EXISTS idx_quarantined_files_user_id ON public.quarantined_files(user_id);
CREATE INDEX IF NOT EXISTS idx_quarantined_files_threat_level ON public.quarantined_files(threat_level);
CREATE INDEX IF NOT EXISTS idx_quarantined_files_auto_delete ON public.quarantined_files(auto_delete_at);
CREATE INDEX IF NOT EXISTS idx_quarantined_files_review_status ON public.quarantined_files(manually_reviewed);

CREATE INDEX IF NOT EXISTS idx_file_uploads_scan_status ON public.file_uploads(scan_status);
CREATE INDEX IF NOT EXISTS idx_file_uploads_file_hash ON public.file_uploads(file_hash);
CREATE INDEX IF NOT EXISTS idx_file_uploads_deleted_at ON public.file_uploads(deleted_at) WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_formal_documents_scan_status ON public.formal_documents(scan_status);
CREATE INDEX IF NOT EXISTS idx_formal_documents_priority ON public.formal_documents(priority_level);
CREATE INDEX IF NOT EXISTS idx_document_validations_validation_status ON public.document_validations(validation_status);

CREATE INDEX IF NOT EXISTS idx_upload_sessions_user_id ON public.file_upload_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_upload_sessions_token ON public.file_upload_sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_upload_sessions_status ON public.file_upload_sessions(status);
CREATE INDEX IF NOT EXISTS idx_upload_sessions_expires_at ON public.file_upload_sessions(expires_at);

-- Create updated_at triggers
CREATE OR REPLACE FUNCTION update_file_uploads_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = TIMEZONE('utc', NOW());
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER trigger_update_file_uploads_updated_at
    BEFORE UPDATE ON public.file_uploads
    FOR EACH ROW
    EXECUTE FUNCTION update_file_uploads_updated_at();

CREATE OR REPLACE FUNCTION update_upload_sessions_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = TIMEZONE('utc', NOW());
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER trigger_update_upload_sessions_updated_at
    BEFORE UPDATE ON public.file_upload_sessions
    FOR EACH ROW
    EXECUTE FUNCTION update_upload_sessions_updated_at();

-- Create function to automatically clean up expired upload sessions
CREATE OR REPLACE FUNCTION cleanup_expired_upload_sessions()
RETURNS void AS $$
BEGIN
    DELETE FROM public.file_upload_sessions 
    WHERE expires_at < TIMEZONE('utc', NOW())
    AND status IN ('initiated', 'failed', 'cancelled');
END;
$$ language 'plpgsql';

-- Create function to automatically delete old quarantined files
CREATE OR REPLACE FUNCTION cleanup_old_quarantined_files()
RETURNS void AS $$
BEGIN
    DELETE FROM public.quarantined_files 
    WHERE auto_delete_at < TIMEZONE('utc', NOW())
    AND manually_reviewed = false;
END;
$$ language 'plpgsql';

-- Create storage buckets for formal documents and quarantine
DO $$
BEGIN
    -- Create formal-documents bucket (private)
    INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
    VALUES (
        'formal-documents',
        'formal-documents',
        false, -- Private bucket
        10485760, -- 10MB limit for formal docs
        ARRAY['application/pdf', 'image/jpeg', 'image/png', 'image/webp']::text[]
    )
    ON CONFLICT (id) DO UPDATE
    SET 
        public = false,
        file_size_limit = 10485760,
        allowed_mime_types = ARRAY['application/pdf', 'image/jpeg', 'image/png', 'image/webp']::text[];

    -- Create quarantine bucket (restricted access)
    INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
    VALUES (
        'quarantine',
        'quarantine',
        false, -- Private bucket
        52428800, -- 50MB
        ARRAY['*']::text[] -- Accept any file type for quarantine
    )
    ON CONFLICT (id) DO UPDATE
    SET 
        public = false,
        file_size_limit = 52428800,
        allowed_mime_types = ARRAY['*']::text[];

    -- Create storage policies for formal-documents bucket
    DROP POLICY IF EXISTS "Authenticated users can upload formal documents" ON storage.objects;
    DROP POLICY IF EXISTS "Users can view own formal documents" ON storage.objects;
    DROP POLICY IF EXISTS "Users can delete own formal documents" ON storage.objects;

    CREATE POLICY "Authenticated users can upload formal documents"
    ON storage.objects FOR INSERT
    TO authenticated
    WITH CHECK (
        bucket_id = 'formal-documents'
        AND (auth.uid() = (storage.foldername(name))[1]::uuid)
    );

    CREATE POLICY "Users can view own formal documents"
    ON storage.objects FOR SELECT
    TO authenticated
    USING (
        bucket_id = 'formal-documents'
        AND (auth.uid() = (storage.foldername(name))[1]::uuid)
    );

    CREATE POLICY "Users can delete own formal documents"
    ON storage.objects FOR DELETE
    TO authenticated
    USING (
        bucket_id = 'formal-documents'
        AND (auth.uid() = (storage.foldername(name))[1]::uuid)
    );

    -- Create storage policies for quarantine bucket (admin only)
    DROP POLICY IF EXISTS "Only system can access quarantine" ON storage.objects;
    
    CREATE POLICY "Only system can access quarantine"
    ON storage.objects FOR ALL
    USING (
        bucket_id = 'quarantine'
        AND false -- No direct access - only through admin interface
    );
END $$;

-- Grant permissions
GRANT ALL ON public.security_logs TO authenticated;
GRANT SELECT ON public.security_logs TO public;
GRANT ALL ON public.quarantined_files TO authenticated;
GRANT ALL ON public.file_upload_sessions TO authenticated;
GRANT SELECT ON public.file_upload_sessions TO public;

-- Add comments for documentation
COMMENT ON TABLE public.security_logs IS 'Comprehensive security event logging with client and network information';
COMMENT ON TABLE public.quarantined_files IS 'Storage tracking for files flagged as potentially malicious';
COMMENT ON TABLE public.file_upload_sessions IS 'Real-time upload progress tracking and session management';

COMMENT ON COLUMN public.security_logs.severity_level IS 'Security event severity: low, medium, high, critical';
COMMENT ON COLUMN public.security_logs.ip_address IS 'Client IP address for geolocation and tracking';
COMMENT ON COLUMN public.quarantined_files.auto_delete_at IS 'Automatic deletion timestamp for quarantined files';
COMMENT ON COLUMN public.file_upload_sessions.progress_percentage IS 'Real-time upload progress (0-100)';