-- Fix message ID format to support AI SDK message IDs (Final attempt)
-- Change message IDs from UUID to TEXT to support AI SDK generated IDs

-- First, drop the foreign key constraint from votes table
ALTER TABLE public.votes DROP CONSTRAINT IF EXISTS votes_message_id_fkey;

-- Change message_id column type in votes table
ALTER TABLE public.votes ALTER COLUMN message_id TYPE TEXT;

-- Change id column type in messages table  
ALTER TABLE public.messages ALTER COLUMN id DROP DEFAULT;
ALTER TABLE public.messages ALTER COLUMN id TYPE TEXT;

-- Re-add the foreign key constraint
ALTER TABLE public.votes ADD CONSTRAINT votes_message_id_fkey 
    FOREIGN KEY (message_id) REFERENCES public.messages(id) ON DELETE CASCADE;

-- Clear any existing problematic data to ensure clean state
DELETE FROM public.votes;
DELETE FROM public.messages;