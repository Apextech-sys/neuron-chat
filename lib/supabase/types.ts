export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[]

export type Database = {
  // Allows to automatically instanciate createClient with right options
  // instead of createClient<Database, { PostgrestVersion: 'XX' }>(URL, KEY)
  __InternalSupabase: {
    PostgrestVersion: "13.0.4"
  }
  public: {
    Tables: {
      chats: {
        Row: {
          created_at: string
          id: string
          title: string | null
          updated_at: string
          user_id: string
        }
        Insert: {
          created_at?: string
          id?: string
          title?: string | null
          updated_at?: string
          user_id: string
        }
        Update: {
          created_at?: string
          id?: string
          title?: string | null
          updated_at?: string
          user_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "chats_user_id_fkey"
            columns: ["user_id"]
            isOneToOne: false
            referencedRelation: "users"
            referencedColumns: ["id"]
          },
        ]
      }
      document_validations: {
        Row: {
          created_at: string
          document_created_at: string
          document_id: string
          id: string
          review_notes: string | null
          reviewed_at: string | null
          reviewer_id: string | null
          updated_at: string | null
          user_id: string
          validation_status:
            | Database["public"]["Enums"]["validation_status_enum"]
            | null
        }
        Insert: {
          created_at?: string
          document_created_at: string
          document_id: string
          id?: string
          review_notes?: string | null
          reviewed_at?: string | null
          reviewer_id?: string | null
          updated_at?: string | null
          user_id: string
          validation_status?:
            | Database["public"]["Enums"]["validation_status_enum"]
            | null
        }
        Update: {
          created_at?: string
          document_created_at?: string
          document_id?: string
          id?: string
          review_notes?: string | null
          reviewed_at?: string | null
          reviewer_id?: string | null
          updated_at?: string | null
          user_id?: string
          validation_status?:
            | Database["public"]["Enums"]["validation_status_enum"]
            | null
        }
        Relationships: [
          {
            foreignKeyName: "document_validations_document_id_fkey"
            columns: ["document_id", "document_created_at"]
            isOneToOne: false
            referencedRelation: "formal_documents"
            referencedColumns: ["id", "created_at"]
          },
          {
            foreignKeyName: "document_validations_document_id_fkey"
            columns: ["document_id", "document_created_at"]
            isOneToOne: false
            referencedRelation: "formal_documents_with_validation"
            referencedColumns: ["id", "created_at"]
          },
          {
            foreignKeyName: "suggestions_user_id_fkey"
            columns: ["user_id"]
            isOneToOne: false
            referencedRelation: "users"
            referencedColumns: ["id"]
          },
        ]
      }
      file_upload_sessions: {
        Row: {
          created_at: string
          current_step: string | null
          document_type: string | null
          error_message: string | null
          expires_at: string | null
          id: string
          metadata: Json | null
          progress_percentage: number | null
          session_token: string
          status: string | null
          updated_at: string
          upload_type: string
          user_id: string | null
        }
        Insert: {
          created_at?: string
          current_step?: string | null
          document_type?: string | null
          error_message?: string | null
          expires_at?: string | null
          id?: string
          metadata?: Json | null
          progress_percentage?: number | null
          session_token: string
          status?: string | null
          updated_at?: string
          upload_type: string
          user_id?: string | null
        }
        Update: {
          created_at?: string
          current_step?: string | null
          document_type?: string | null
          error_message?: string | null
          expires_at?: string | null
          id?: string
          metadata?: Json | null
          progress_percentage?: number | null
          session_token?: string
          status?: string | null
          updated_at?: string
          upload_type?: string
          user_id?: string | null
        }
        Relationships: []
      }
      documents: {
        Row: {
          id: string
          user_id: string
          title: string
          content: string
          created_at: string
        }
        Insert: {
          id: string
          user_id: string
          title: string
          content: string
          created_at: string
        }
        Update: {
          id?: string
          user_id?: string
          title?: string
          content?: string
          created_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "documents_user_id_fkey"
            columns: ["user_id"]
            isOneToOne: false
            referencedRelation: "users"
            referencedColumns: ["id"]
          },
        ]
      }
      suggestions: {
        Row: {
          id: string
          document_id: string
          document_created_at: string
          original_text: string
          suggested_text: string
          description: string
          user_id: string
          is_resolved: boolean
          created_at: string
        }
        Insert: {
          id?: string
          document_id: string
          document_created_at: string
          original_text: string
          suggested_text: string
          description: string
          user_id: string
          is_resolved?: boolean
          created_at?: string
        }
        Update: {
          id?: string
          document_id?: string
          document_created_at?: string
          original_text?: string
          suggested_text?: string
          description?: string
          user_id?: string
          is_resolved?: boolean
          created_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "suggestions_document_id_fkey"
            columns: ["document_id", "document_created_at"]
            isOneToOne: false
            referencedRelation: "documents"
            referencedColumns: ["id", "created_at"]
          },
          {
            foreignKeyName: "suggestions_user_id_fkey"
            columns: ["user_id"]
            isOneToOne: false
            referencedRelation: "users"
            referencedColumns: ["id"]
          },
        ]
      }
      file_uploads: {
        Row: {
          bucket_id: string
          chat_id: string
          content_type: string
          created_at: string
          deleted_at: string | null
          file_hash: string | null
          filename: string
          id: string
          original_name: string
          scan_date: string | null
          scan_details: Json | null
          scan_status: string | null
          size: number
          storage_path: string
          updated_at: string | null
          url: string
          user_id: string
          version: number
          virustotal_analysis: Json | null
          virustotal_id: string | null
        }
        Insert: {
          bucket_id?: string
          chat_id: string
          content_type: string
          created_at?: string
          deleted_at?: string | null
          file_hash?: string | null
          filename: string
          id?: string
          original_name: string
          scan_date?: string | null
          scan_details?: Json | null
          scan_status?: string | null
          size: number
          storage_path: string
          updated_at?: string | null
          url: string
          user_id: string
          version?: number
          virustotal_analysis?: Json | null
          virustotal_id?: string | null
        }
        Update: {
          bucket_id?: string
          chat_id?: string
          content_type?: string
          created_at?: string
          deleted_at?: string | null
          file_hash?: string | null
          filename?: string
          id?: string
          original_name?: string
          scan_date?: string | null
          scan_details?: Json | null
          scan_status?: string | null
          size?: number
          storage_path?: string
          updated_at?: string | null
          url?: string
          user_id?: string
          version?: number
          virustotal_analysis?: Json | null
          virustotal_id?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "file_uploads_chat_id_fkey"
            columns: ["chat_id"]
            isOneToOne: false
            referencedRelation: "chats"
            referencedColumns: ["id"]
          },
        ]
      }
      formal_documents: {
        Row: {
          content: string | null
          created_at: string
          document_type:
            | Database["public"]["Enums"]["document_type_enum"]
            | null
          file_reference_id: string | null
          id: string
          priority_level: string | null
          reviewed_by: string | null
          scan_details: Json | null
          scan_status: string | null
          submission_notes: string | null
          title: string
          updated_at: string | null
          user_id: string
          validation_notes: string | null
          virustotal_analysis: Json | null
        }
        Insert: {
          content?: string | null
          created_at?: string
          document_type?:
            | Database["public"]["Enums"]["document_type_enum"]
            | null
          file_reference_id?: string | null
          id?: string
          priority_level?: string | null
          reviewed_by?: string | null
          scan_details?: Json | null
          scan_status?: string | null
          submission_notes?: string | null
          title: string
          updated_at?: string | null
          user_id: string
          validation_notes?: string | null
          virustotal_analysis?: Json | null
        }
        Update: {
          content?: string | null
          created_at?: string
          document_type?:
            | Database["public"]["Enums"]["document_type_enum"]
            | null
          file_reference_id?: string | null
          id?: string
          priority_level?: string | null
          reviewed_by?: string | null
          scan_details?: Json | null
          scan_status?: string | null
          submission_notes?: string | null
          title?: string
          updated_at?: string | null
          user_id?: string
          validation_notes?: string | null
          virustotal_analysis?: Json | null
        }
        Relationships: [
          {
            foreignKeyName: "documents_user_id_fkey"
            columns: ["user_id"]
            isOneToOne: false
            referencedRelation: "users"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "formal_documents_file_reference_id_fkey"
            columns: ["file_reference_id"]
            isOneToOne: false
            referencedRelation: "file_uploads"
            referencedColumns: ["id"]
          },
        ]
      }
      messages: {
        Row: {
          chat_id: string
          content: Json
          created_at: string
          id: string
          role: string
          updated_at: string
        }
        Insert: {
          chat_id: string
          content: Json
          created_at?: string
          id: string
          role: string
          updated_at?: string
        }
        Update: {
          chat_id?: string
          content?: Json
          created_at?: string
          id?: string
          role?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "messages_chat_id_fkey"
            columns: ["chat_id"]
            isOneToOne: false
            referencedRelation: "chats"
            referencedColumns: ["id"]
          },
        ]
      }
      quarantined_files: {
        Row: {
          auto_delete_at: string | null
          file_hash: string
          file_name: string
          id: string
          manually_reviewed: boolean | null
          original_file_id: string | null
          quarantine_path: string
          quarantined_at: string
          review_notes: string | null
          reviewed_at: string | null
          reviewed_by: string | null
          threat_details: Json | null
          threat_level: string
          user_id: string | null
        }
        Insert: {
          auto_delete_at?: string | null
          file_hash: string
          file_name: string
          id?: string
          manually_reviewed?: boolean | null
          original_file_id?: string | null
          quarantine_path: string
          quarantined_at?: string
          review_notes?: string | null
          reviewed_at?: string | null
          reviewed_by?: string | null
          threat_details?: Json | null
          threat_level: string
          user_id?: string | null
        }
        Update: {
          auto_delete_at?: string | null
          file_hash?: string
          file_name?: string
          id?: string
          manually_reviewed?: boolean | null
          original_file_id?: string | null
          quarantine_path?: string
          quarantined_at?: string
          review_notes?: string | null
          reviewed_at?: string | null
          reviewed_by?: string | null
          threat_details?: Json | null
          threat_level?: string
          user_id?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "quarantined_files_original_file_id_fkey"
            columns: ["original_file_id"]
            isOneToOne: false
            referencedRelation: "file_uploads"
            referencedColumns: ["id"]
          },
        ]
      }
      security_logs: {
        Row: {
          browser_info: string | null
          city: string | null
          country_code: string | null
          created_at: string
          device_info: string | null
          event_type: string
          file_hash: string | null
          file_name: string | null
          id: string
          ip_address: unknown | null
          os_info: string | null
          resolution_notes: string | null
          resolved: boolean | null
          resolved_at: string | null
          resolved_by: string | null
          session_id: string | null
          severity_level: string | null
          threat_details: Json | null
          user_agent: string | null
          user_id: string | null
        }
        Insert: {
          browser_info?: string | null
          city?: string | null
          country_code?: string | null
          created_at?: string
          device_info?: string | null
          event_type: string
          file_hash?: string | null
          file_name?: string | null
          id?: string
          ip_address?: unknown | null
          os_info?: string | null
          resolution_notes?: string | null
          resolved?: boolean | null
          resolved_at?: string | null
          resolved_by?: string | null
          session_id?: string | null
          severity_level?: string | null
          threat_details?: Json | null
          user_agent?: string | null
          user_id?: string | null
        }
        Update: {
          browser_info?: string | null
          city?: string | null
          country_code?: string | null
          created_at?: string
          device_info?: string | null
          event_type?: string
          file_hash?: string | null
          file_name?: string | null
          id?: string
          ip_address?: unknown | null
          os_info?: string | null
          resolution_notes?: string | null
          resolved?: boolean | null
          resolved_at?: string | null
          resolved_by?: string | null
          session_id?: string | null
          severity_level?: string | null
          threat_details?: Json | null
          user_agent?: string | null
          user_id?: string | null
        }
        Relationships: []
      }
      users: {
        Row: {
          created_at: string
          email: string
          id: string
          updated_at: string
        }
        Insert: {
          created_at?: string
          email: string
          id?: string
          updated_at?: string
        }
        Update: {
          created_at?: string
          email?: string
          id?: string
          updated_at?: string
        }
        Relationships: []
      }
      votes: {
        Row: {
          chat_id: string
          is_upvoted: boolean
          message_id: string
          updated_at: string | null
        }
        Insert: {
          chat_id: string
          is_upvoted: boolean
          message_id: string
          updated_at?: string | null
        }
        Update: {
          chat_id?: string
          is_upvoted?: boolean
          message_id?: string
          updated_at?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "votes_chat_id_fkey"
            columns: ["chat_id"]
            isOneToOne: false
            referencedRelation: "chats"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "votes_message_id_fkey"
            columns: ["message_id"]
            isOneToOne: false
            referencedRelation: "messages"
            referencedColumns: ["id"]
          },
        ]
      }
    }
    Views: {
      formal_documents_with_validation: {
        Row: {
          content: string | null
          created_at: string | null
          document_type:
            | Database["public"]["Enums"]["document_type_enum"]
            | null
          file_name: string | null
          file_reference_id: string | null
          file_type: string | null
          file_url: string | null
          id: string | null
          review_notes: string | null
          reviewed_at: string | null
          reviewer_id: string | null
          submission_notes: string | null
          title: string | null
          updated_at: string | null
          user_id: string | null
          validation_status:
            | Database["public"]["Enums"]["validation_status_enum"]
            | null
        }
        Relationships: [
          {
            foreignKeyName: "documents_user_id_fkey"
            columns: ["user_id"]
            isOneToOne: false
            referencedRelation: "users"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "formal_documents_file_reference_id_fkey"
            columns: ["file_reference_id"]
            isOneToOne: false
            referencedRelation: "file_uploads"
            referencedColumns: ["id"]
          },
        ]
      }
    }
    Functions: {
      cleanup_expired_upload_sessions: {
        Args: Record<PropertyKey, never>
        Returns: undefined
      }
      cleanup_old_quarantined_files: {
        Args: Record<PropertyKey, never>
        Returns: undefined
      }
      get_document_latest_version: {
        Args: { doc_id: string }
        Returns: string
      }
      get_latest_document: {
        Args: { doc_id: string; auth_user_id: string }
        Returns: {
          id: string
          user_id: string
          title: string
          content: string
          created_at: string
        }[]
      }
      get_latest_formal_document: {
        Args: { doc_id: string; auth_user_id: string }
        Returns: {
          id: string
          user_id: string
          title: string
          content: string
          created_at: string
        }[]
      }
      get_next_file_version: {
        Args: { p_bucket_id: string; p_storage_path: string }
        Returns: number
      }
      gtrgm_compress: {
        Args: { "": unknown }
        Returns: unknown
      }
      gtrgm_decompress: {
        Args: { "": unknown }
        Returns: unknown
      }
      gtrgm_in: {
        Args: { "": unknown }
        Returns: unknown
      }
      gtrgm_options: {
        Args: { "": unknown }
        Returns: undefined
      }
      gtrgm_out: {
        Args: { "": unknown }
        Returns: unknown
      }
      set_limit: {
        Args: { "": number }
        Returns: number
      }
      show_limit: {
        Args: Record<PropertyKey, never>
        Returns: number
      }
      show_trgm: {
        Args: { "": string }
        Returns: string[]
      }
    }
    Enums: {
      document_type_enum:
        | "proof_of_address"
        | "proof_of_payment"
        | "identification"
        | "debit_order_authorisation"
      validation_status_enum:
        | "pending_review"
        | "under_review"
        | "approved"
        | "rejected"
        | "requires_resubmission"
    }
    CompositeTypes: {
      [_ in never]: never
    }
  }
}

type DatabaseWithoutInternals = Omit<Database, "__InternalSupabase">

type DefaultSchema = DatabaseWithoutInternals[Extract<keyof Database, "public">]

export type Tables<
  DefaultSchemaTableNameOrOptions extends
    | keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
        DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
      DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])[TableName] extends {
      Row: infer R
    }
    ? R
    : never
  : DefaultSchemaTableNameOrOptions extends keyof (DefaultSchema["Tables"] &
        DefaultSchema["Views"])
    ? (DefaultSchema["Tables"] &
        DefaultSchema["Views"])[DefaultSchemaTableNameOrOptions] extends {
        Row: infer R
      }
      ? R
      : never
    : never

export type TablesInsert<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Insert: infer I
    }
    ? I
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Insert: infer I
      }
      ? I
      : never
    : never

export type TablesUpdate<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Update: infer U
    }
    ? U
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Update: infer U
      }
      ? U
      : never
    : never

export type Enums<
  DefaultSchemaEnumNameOrOptions extends
    | keyof DefaultSchema["Enums"]
    | { schema: keyof DatabaseWithoutInternals },
  EnumName extends DefaultSchemaEnumNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"]
    : never = never,
> = DefaultSchemaEnumNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"][EnumName]
  : DefaultSchemaEnumNameOrOptions extends keyof DefaultSchema["Enums"]
    ? DefaultSchema["Enums"][DefaultSchemaEnumNameOrOptions]
    : never

export type CompositeTypes<
  PublicCompositeTypeNameOrOptions extends
    | keyof DefaultSchema["CompositeTypes"]
    | { schema: keyof DatabaseWithoutInternals },
  CompositeTypeName extends PublicCompositeTypeNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"]
    : never = never,
> = PublicCompositeTypeNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"][CompositeTypeName]
  : PublicCompositeTypeNameOrOptions extends keyof DefaultSchema["CompositeTypes"]
    ? DefaultSchema["CompositeTypes"][PublicCompositeTypeNameOrOptions]
    : never

export const Constants = {
  public: {
    Enums: {
      document_type_enum: [
        "proof_of_address",
        "proof_of_payment",
        "identification",
        "debit_order_authorisation",
      ],
      validation_status_enum: [
        "pending_review",
        "under_review",
        "approved",
        "rejected",
        "requires_resubmission",
      ],
    },
  },
} as const
