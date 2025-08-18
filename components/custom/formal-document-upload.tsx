'use client';

import React, { useState, useRef, useCallback, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { toast } from 'sonner';
import cx from 'classnames';

import { Button } from '@/components/ui/button';
import { 
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Progress } from '@/components/ui/progress';
import { Badge } from '../ui/badge';
import { Database } from '@/lib/supabase/types';
type DocumentType = Database['public']['Enums']['document_type_enum'];

// Icons - using available icons from the icons file
import { FileIcon, ChevronDownIcon, CheckCirclFillIcon, CrossIcon, LoaderIcon, InfoIcon } from './icons';

type StepStatus = 'pending' | 'active' | 'completed' | 'failed';
type UploadStatus = 'initiated' | 'uploading' | 'validating' | 'queued' | 'scanning' | 'completed' | 'failed';

interface DocumentUploadProgress {
  fileName: string;
  documentType: DocumentType;
  progress: number;
  status: UploadStatus;
  error?: string;
  sessionToken?: string;
  steps: { name: string; status: StepStatus }[];
}

interface FormalDocumentUploadProps {
  chatId: string;
  disabled?: boolean;
  className?: string;
}

const documentTypeLabels: Record<DocumentType, string> = {
  'proof_of_address': 'Proof of Address',
  'proof_of_payment': 'Proof of Payment',
  'identification': 'ID Document',
  'debit_order_authorisation': 'Debit Order Authorization'
};

const documentTypeDescriptions: Record<DocumentType, string> = {
  'proof_of_address': 'Utility bill, bank statement, or official document showing your address',
  'proof_of_payment': 'Receipt or bank statement showing payment made',
  'identification': 'South African ID document, passport, or driver\'s license',
  'debit_order_authorisation': 'Signed debit order form for payment authorization'
};

const allowedFileTypes = [
  'image/jpeg',
  'image/png', 
  'image/webp',
  'application/pdf',
  'image/tiff'
];

const maxFileSize = 10 * 1024 * 1024; // 10MB

export function FormalDocumentUpload({ chatId, disabled = false, className }: FormalDocumentUploadProps) {
  const [uploads, setUploads] = useState<DocumentUploadProgress[]>([]);
  const [isDropdownOpen, setIsDropdownOpen] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [selectedDocumentType, setSelectedDocumentType] = useState<DocumentType | null>(null);

  // Track mounted state and pending timers to avoid memory leaks
  const isMountedRef = useRef(true);
  const timeoutsRef = useRef<number[]>([]);

  useEffect(() => {
    return () => {
      isMountedRef.current = false;
      // Clear pending timers
      for (const t of timeoutsRef.current) {
        clearTimeout(t);
      }
      timeoutsRef.current = [];
    };
  }, []);

  const validateFile = useCallback((file: File, documentType: DocumentType) => {
    // Check file size
    if (file.size > maxFileSize) {
      throw new Error(`File size must be less than ${maxFileSize / (1024 * 1024)}MB`);
    }

    // Check file type
    if (!allowedFileTypes.includes(file.type)) {
      throw new Error('File type not supported. Please use PDF, JPEG, PNG, WebP, or TIFF files.');
    }

    // Additional validation based on document type
    if (documentType === 'identification' && file.type.startsWith('image/')) {
      // For ID documents, we might want higher resolution images
      // This validation would happen on the backend, but we can add client-side hints
    }

    return true;
  }, []);

  const uploadFormalDocument = useCallback(async (file: File, documentType: DocumentType): Promise<string> => {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('documentType', documentType);
    formData.append('chatId', chatId);

    const response = await fetch('/api/formal-documents/upload', {
      method: 'POST',
      body: formData,
    });

    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.error || 'Upload failed');
    }

    const result = await response.json();
    
    // Check if session was created successfully
    if (result.success && result.sessionToken) {
      return result.sessionToken;
    } else {
      throw new Error(result.error || 'Failed to create upload session');
    }
  }, [chatId]);


  const pollUploadProgress = useCallback(async (sessionToken: string, fileName: string) => {
    const maxAttempts = 60; // 5 minutes max
    let attempts = 0;

    const poll = async () => {
      try {
        const response = await fetch(`/api/formal-documents/upload/status?sessionToken=${sessionToken}`);
        if (!response.ok) {
          throw new Error(`Status check failed: ${response.status}`);
        }

        const data = await response.json() as {
          status: UploadStatus,
          progress_percentage?: number,
          error_message?: string
        };

        if (!isMountedRef.current) {
          return;
        }

        setUploads(current =>
          current.map(upload => {
            if (upload.sessionToken !== sessionToken) return upload;

            const { status: apiStatus, error_message } = data;
            
            const stepMap: Record<string, number> = { 'uploading': 0, 'queued': 1, 'validating': 1, 'scanning': 2 };
            const activeStepIndex = stepMap[apiStatus] ?? -1;

            const finalSteps: typeof upload.steps = upload.steps.map((step, index): typeof step => {
              if (apiStatus === 'completed') return { ...step, status: 'completed' };
              if (apiStatus === 'failed') {
                return (index === activeStepIndex || step.status === 'active') ? { ...step, status: 'failed' } : step;
              }
              if (activeStepIndex > -1) {
                if (index < activeStepIndex) return { ...step, status: 'completed' };
                if (index === activeStepIndex) return { ...step, status: 'active' };
                return { ...step, status: 'pending' };
              }
              return step;
            });

            return {
              ...upload,
              status: apiStatus,
              error: error_message,
              steps: finalSteps,
            };
          })
        );

        if (data.status === 'completed') {
          if (isMountedRef.current) {
            toast.success(`${fileName} uploaded and validated successfully!`);
          }
          return;
        }

        if (data.status === 'failed') {
          if (isMountedRef.current) {
            toast.error(`Failed to upload ${fileName}: ${data.error_message}`);
          }
          return;
        }

        attempts++;
        if (attempts < maxAttempts && ['initiated', 'uploading', 'validating', 'scanning'].includes(data.status)) {
          const t = window.setTimeout(poll, 5000);
          timeoutsRef.current.push(t);
        } else if (attempts >= maxAttempts) {
          if (!isMountedRef.current) return;

          setUploads(current =>
            current.map(upload =>
              upload.sessionToken === sessionToken
                ? { ...upload, status: 'failed', error: 'Upload timeout' }
                : upload
            )
          );
          toast.error(`Upload timeout for ${fileName}`);
        }
      } catch (error) {
        console.error('Error polling upload status:', error);
        if (!isMountedRef.current) return;

        setUploads(current =>
          current.map(upload =>
            upload.sessionToken === sessionToken
              ? { ...upload, status: 'failed', error: 'Connection error' }
              : upload
          )
        );
        toast.error(`Connection error while uploading ${fileName}`);
      }
    };

    poll();
  }, []);

  const handleFileUpload = useCallback(async (file: File, documentType: DocumentType) => {
    try {
      validateFile(file, documentType);

      // Add to uploads list with initial steps
      setUploads(current => [...current, {
        fileName: file.name,
        documentType,
        progress: 0,
        status: 'uploading',
        steps: [
          { name: 'Uploading', status: 'active' },
          { name: 'Queued', status: 'pending' },
          { name: 'Scanning', status: 'pending' },
        ],
      }]);

      // Start upload and get session token
      const sessionToken = await uploadFormalDocument(file, documentType);
      
      // Update with session token
      setUploads(current =>
        current.map(upload =>
          upload.fileName === file.name && upload.documentType === documentType
            ? { ...upload, sessionToken, progress: 10, status: 'uploading' }
            : upload
        )
      );

      // Start polling for progress
      pollUploadProgress(sessionToken, file.name);

    } catch (error) {
      console.error('Upload error:', error);
      const errorMessage = error instanceof Error ? error.message : 'Upload failed';
      
      setUploads(current =>
        current.map(upload =>
          upload.fileName === file.name && upload.documentType === documentType
            ? { ...upload, status: 'failed', error: errorMessage }
            : upload
        )
      );

      toast.error(`Failed to upload ${file.name}: ${errorMessage}`);
    }
  }, [validateFile, uploadFormalDocument, pollUploadProgress]);

  const handleDocumentTypeSelect = useCallback((documentType: DocumentType) => {
    setSelectedDocumentType(documentType);
    setIsDropdownOpen(false);
    fileInputRef.current?.click();
  }, []);

  const handleFileChange = useCallback((event: React.ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(event.target.files || []);
    if (files.length > 0 && selectedDocumentType) {
      files.forEach(file => handleFileUpload(file, selectedDocumentType));
    }
    // Reset file input
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
    setSelectedDocumentType(null);
  }, [selectedDocumentType, handleFileUpload]);

  const removeUpload = useCallback((index: number) => {
    setUploads(current => current.filter((_, i) => i !== index));
  }, []);

  const getStatusIcon = (status: UploadStatus) => {
    switch (status) {
      case 'completed':
        return <div className="text-green-500"><CheckCirclFillIcon size={20} /></div>;
      case 'failed':
        return <div className="text-red-500"><InfoIcon size={20} /></div>;
      default:
        return <div className="animate-spin text-muted-foreground"><LoaderIcon size={20} /></div>;
    }
  };

  const UploadStep = ({ name, status }: { name: string; status: 'pending' | 'active' | 'completed' | 'failed' }) => {
    const statusClasses = {
      pending: 'border-muted-foreground/20 text-muted-foreground',
      active: 'border-primary text-primary animate-pulse',
      completed: 'border-green-500 bg-green-500/10 text-green-500',
      failed: 'border-red-500 bg-red-500/10 text-red-500',
    };
    const Icon = status === 'completed' ? CheckCirclFillIcon : status === 'failed' ? InfoIcon : LoaderIcon;
    return (
      <div className={`flex items-center space-x-2 text-xs p-1.5 border rounded-md ${statusClasses[status]}`}>
        <div className={status === 'active' ? 'animate-spin' : ''}><Icon size={12} /></div>
        <span>{name}</span>
      </div>
    );
  };

  return (
    <div className={cx('relative', className)}>
      <input
        type="file"
        ref={fileInputRef}
        className="hidden"
        multiple
        accept={allowedFileTypes.join(',')}
        onChange={handleFileChange}
      />

      {/* Upload Progress Display */}
      <AnimatePresence>
        {uploads.length > 0 && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            className="mb-4 space-y-2"
          >
            {uploads.map((upload, index) => (
              <motion.div
                key={`${upload.fileName}-${upload.documentType}-${index}`}
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                className="bg-muted rounded-lg p-3 space-y-2"
              >
                <div className="flex items-start justify-between">
                  <div className="flex items-start space-x-3">
                    {getStatusIcon(upload.status)}
                    <div>
                      <p className="text-sm font-medium">{upload.fileName}</p>
                      <p className="text-xs text-muted-foreground">{documentTypeLabels[upload.documentType]}</p>
                    </div>
                  </div>
                  {(upload.status === 'completed' || upload.status === 'failed') && (
                    <Button variant="ghost" size="sm" onClick={() => removeUpload(index)} className="h-6 w-6 p-0">
                      <CrossIcon size={12} />
                    </Button>
                  )}
                </div>

                <div className="space-y-2 pt-2">
                  <div className="flex space-x-2">
                    {upload.steps.map(step => (
                      <UploadStep key={step.name} {...step} />
                    ))}
                  </div>

                  {upload.status === 'scanning' && (
                     <p className="text-xs text-muted-foreground text-center animate-pulse">
                       Scan in progress. This may take a moment, please wait...
                     </p>
                  )}

                  {upload.error && (
                    <p className="text-xs text-red-500">{upload.error}</p>
                  )}
                </div>
              </motion.div>
            ))}
          </motion.div>
        )}
      </AnimatePresence>

      {/* Document Type Selector */}
      <DropdownMenu open={isDropdownOpen} onOpenChange={setIsDropdownOpen}>
        <DropdownMenuTrigger asChild>
          <Button
            variant="outline"
            disabled={disabled}
            className="rounded-full h-fit p-1.5 m-0.5 border"
          >
            <FileIcon size={14} />
            <ChevronDownIcon size={10} />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-80">
          <div className="p-2 border-b">
            <h4 className="font-medium text-sm">Upload Formal Document</h4>
            <p className="text-xs text-muted-foreground mt-1">
              Select document type and upload your file for validation
            </p>
          </div>
          {(Object.entries(documentTypeLabels) as [DocumentType, string][]).map(([type, label]) => (
            <DropdownMenuItem
              key={type}
              onClick={() => handleDocumentTypeSelect(type)}
              className="flex flex-col items-start p-3 space-y-1 cursor-pointer"
            >
              <div className="font-medium text-sm">{label}</div>
              <div className="text-xs text-muted-foreground">
                {documentTypeDescriptions[type]}
              </div>
            </DropdownMenuItem>
          ))}
          <div className="p-2 border-t">
            <p className="text-xs text-muted-foreground">
              Supported: PDF, JPEG, PNG, WebP, TIFF (max {maxFileSize / (1024 * 1024)}MB)
            </p>
          </div>
        </DropdownMenuContent>
      </DropdownMenu>
    </div>
  );
}