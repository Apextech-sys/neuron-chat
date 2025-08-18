-- Add columns to store VirusTotal analysis results

-- Add to file_uploads table
ALTER TABLE public.file_uploads
ADD COLUMN virustotal_analysis JSONB;

COMMENT ON COLUMN public.file_uploads.virustotal_analysis IS 'Stores the full analysis report from VirusTotal.';

-- Add to formal_documents table
ALTER TABLE public.formal_documents
ADD COLUMN virustotal_analysis JSONB;

COMMENT ON COLUMN public.formal_documents.virustotal_analysis IS 'Stores the full analysis report from VirusTotal for the associated file.';

-- Create indexes for faster querying
CREATE INDEX idx_file_uploads_virustotal_analysis ON public.file_uploads USING GIN (virustotal_analysis);
CREATE INDEX idx_formal_documents_virustotal_analysis ON public.formal_documents USING GIN (virustotal_analysis);