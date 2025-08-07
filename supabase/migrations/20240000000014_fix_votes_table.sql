-- Fix votes table structure and add missing updated_at field

-- Add updated_at field to votes table if it doesn't exist
ALTER TABLE public.votes ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE DEFAULT TIMEZONE('utc', NOW());

-- Create a function to automatically update the updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = TIMEZONE('utc', NOW());
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create trigger for votes table
DROP TRIGGER IF EXISTS update_votes_updated_at ON public.votes;
CREATE TRIGGER update_votes_updated_at 
    BEFORE UPDATE ON public.votes 
    FOR EACH ROW EXECUTE PROCEDURE update_updated_at_column();