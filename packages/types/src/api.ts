export interface ApiResponse<T> { data?: T; error?: ApiError; meta?: Record<string, any>; } export interface ApiError { code: string; message: string; request_id: string; }
