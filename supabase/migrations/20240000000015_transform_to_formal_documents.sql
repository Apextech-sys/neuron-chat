-- Transform legacy documents/suggestions system into formal document validation system
-- for ISP customer support

-- First, backup existing data (optional step for safety)
-- CREATE TABLE documents_backup AS SELECT * FROM public.documents;
-- CREATE TABLE suggestions_backup AS SELECT * FROM public.suggestions;

-- Drop existing foreign key constraints and indexes
DROP INDEX IF EXISTS idx_suggestions_document_id;
DROP INDEX IF EXISTS idx_suggestions_user_id;
DROP INDEX IF EXISTS idx_suggestions_is_resolved;
DROP INDEX IF EXISTS idx_suggestions_created_at;
DROP INDEX IF EXISTS idx_suggestions_unresolved;

-- Transform documents table into formal_documents
ALTER TABLE public.documents RENAME TO formal_documents;

-- Add new columns to formal_documents
ALTER TABLE public.formal_documents 
ADD COLUMN document_type TEXT,
ADD COLUMN file_reference_id UUID REFERENCES public.file_uploads(id) ON DELETE SET NULL,
ADD COLUMN submission_notes TEXT,
ADD COLUMN updated_at TIMESTAMP WITH TIME ZONE DEFAULT TIMEZONE('utc', NOW());

-- Create ENUM for document types (South African ISP standard documents)
CREATE TYPE document_type_enum AS ENUM (
    'proof_of_address',
    'proof_of_payment', 
    'identification',
    'debit_order_authorisation'
);

-- Update document_type column to use ENUM (set a default value first)
ALTER TABLE public.formal_documents
ALTER COLUMN document_type TYPE document_type_enum USING 'proof_of_address'::document_type_enum;

-- Set default value for document_type
ALTER TABLE public.formal_documents
ALTER COLUMN document_type SET DEFAULT 'proof_of_address'::document_type_enum;

-- Create updated_at trigger for formal_documents
CREATE OR REPLACE FUNCTION update_formal_documents_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = TIMEZONE('utc', NOW());
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_formal_documents_updated_at
    BEFORE UPDATE ON public.formal_documents
    FOR EACH ROW
    EXECUTE FUNCTION update_formal_documents_updated_at();

-- Transform suggestions table into document_validations
ALTER TABLE public.suggestions RENAME TO document_validations;

-- Remove old columns and add new validation-specific columns
ALTER TABLE public.document_validations 
DROP COLUMN original_text,
DROP COLUMN suggested_text,
DROP COLUMN description,
DROP COLUMN is_resolved;

-- Add new validation columns
ALTER TABLE public.document_validations
ADD COLUMN validation_status TEXT,
ADD COLUMN reviewer_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
ADD COLUMN review_notes TEXT,
ADD COLUMN reviewed_at TIMESTAMP WITH TIME ZONE,
ADD COLUMN updated_at TIMESTAMP WITH TIME ZONE DEFAULT TIMEZONE('utc', NOW());

-- Create ENUM for validation status
CREATE TYPE validation_status_enum AS ENUM (
    'pending_review',
    'under_review',
    'approved',
    'rejected',
    'requires_resubmission'
);

-- Update validation_status column to use ENUM
ALTER TABLE public.document_validations
ALTER COLUMN validation_status TYPE validation_status_enum USING 'pending_review'::validation_status_enum;

-- Set default value for validation_status
ALTER TABLE public.document_validations
ALTER COLUMN validation_status SET DEFAULT 'pending_review'::validation_status_enum;

-- Update foreign key constraint to reference formal_documents
ALTER TABLE public.document_validations 
DROP CONSTRAINT suggestions_document_id_document_created_at_fkey;

ALTER TABLE public.document_validations 
ADD CONSTRAINT document_validations_document_id_fkey 
FOREIGN KEY (document_id, document_created_at) 
REFERENCES public.formal_documents(id, created_at) ON DELETE CASCADE;

-- Create updated_at trigger for document_validations
CREATE OR REPLACE FUNCTION update_document_validations_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = TIMEZONE('utc', NOW());
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_document_validations_updated_at
    BEFORE UPDATE ON public.document_validations
    FOR EACH ROW
    EXECUTE FUNCTION update_document_validations_updated_at();

-- Create indexes for performance
CREATE INDEX idx_formal_documents_user_id ON public.formal_documents(user_id);
CREATE INDEX idx_formal_documents_document_type ON public.formal_documents(document_type);
CREATE INDEX idx_formal_documents_created_at ON public.formal_documents(created_at);
CREATE INDEX idx_formal_documents_updated_at ON public.formal_documents(updated_at);

CREATE INDEX idx_document_validations_document_id ON public.document_validations(document_id);
CREATE INDEX idx_document_validations_user_id ON public.document_validations(user_id);
CREATE INDEX idx_document_validations_validation_status ON public.document_validations(validation_status);
CREATE INDEX idx_document_validations_reviewer_id ON public.document_validations(reviewer_id);
CREATE INDEX idx_document_validations_created_at ON public.document_validations(created_at);
CREATE INDEX idx_document_validations_updated_at ON public.document_validations(updated_at);

-- Create partial index for pending validations (most common query)
CREATE INDEX idx_document_validations_pending 
ON public.document_validations(created_at) 
WHERE validation_status = 'pending_review';

-- Update RLS policies for formal_documents
DROP POLICY IF EXISTS "Users can view own documents" ON public.formal_documents;
DROP POLICY IF EXISTS "Users can create own documents" ON public.formal_documents;

CREATE POLICY "Users can view own formal documents" 
ON public.formal_documents FOR SELECT 
USING (auth.uid() = user_id);

CREATE POLICY "Users can create own formal documents" 
ON public.formal_documents FOR INSERT 
WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update own formal documents" 
ON public.formal_documents FOR UPDATE 
USING (auth.uid() = user_id);

-- Update RLS policies for document_validations  
DROP POLICY IF EXISTS "Users can view own suggestions" ON public.document_validations;
DROP POLICY IF EXISTS "Users can create own suggestions" ON public.document_validations;

CREATE POLICY "Users can view own document validations" 
ON public.document_validations FOR SELECT 
USING (auth.uid() = user_id);

CREATE POLICY "Users can create document validations" 
ON public.document_validations FOR INSERT 
WITH CHECK (auth.uid() = user_id);

-- Staff/admin policy for reviewing documents (add staff role later)
-- CREATE POLICY "Staff can review all validations" 
-- ON public.document_validations FOR ALL
-- USING (EXISTS (SELECT 1 FROM auth.users WHERE id = auth.uid() AND role = 'staff'));

-- Create a view for easy querying of documents with their validation status
CREATE OR REPLACE VIEW formal_documents_with_validation AS
SELECT 
    fd.id,
    fd.title,
    fd.content,
    fd.document_type,
    fd.file_reference_id,
    fd.submission_notes,
    fd.user_id,
    fd.created_at,
    fd.updated_at,
    dv.validation_status,
    dv.reviewer_id,
    dv.review_notes,
    dv.reviewed_at,
    fu.url as file_url,
    fu.filename as file_name,
    fu.content_type as file_type
FROM public.formal_documents fd
LEFT JOIN public.document_validations dv ON fd.id = dv.document_id 
    AND fd.created_at = dv.document_created_at
LEFT JOIN public.file_uploads fu ON fd.file_reference_id = fu.id;

-- Grant permissions on the view
GRANT SELECT ON formal_documents_with_validation TO authenticated;

-- Add comments for documentation
COMMENT ON TABLE public.formal_documents IS 'Stores metadata for formal customer documents (proof of address, ID, etc.)';
COMMENT ON TABLE public.document_validations IS 'Tracks validation workflow and review status for formal documents';
COMMENT ON TYPE document_type_enum IS 'Standard document types required for ISP customer verification';
COMMENT ON TYPE validation_status_enum IS 'Document validation workflow states';

-- Update database functions that referenced old table names
DROP FUNCTION IF EXISTS get_latest_document(doc_id text, auth_user_id text);

CREATE OR REPLACE FUNCTION get_latest_formal_document(
    doc_id TEXT,
    auth_user_id TEXT
) RETURNS TABLE (
    id TEXT,
    user_id TEXT,
    title TEXT,
    content TEXT,
    created_at TEXT
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        fd.id::TEXT,
        fd.user_id::TEXT,
        fd.title,
        fd.content,
        fd.created_at::TEXT
    FROM public.formal_documents fd
    WHERE fd.id::TEXT = doc_id 
    AND fd.user_id::TEXT = auth_user_id
    ORDER BY fd.created_at DESC
    LIMIT 1;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;