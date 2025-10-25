import {
	SafeApiResponse,
	BackendError,
	BackendResponse,
} from '../../types/index.js';
import {getSessionToken} from '../../utils/token/utils.sessionToken.js';
import {
	useMutation,
	UseMutationOptions,
	UseMutationResult,
} from '@tanstack/react-query';

export type TypedMutationOptions<TRequest, TResponse> = Omit<
	UseMutationOptions<SafeApiResponse<TResponse>, never, TRequest>,
	'mutationFn'
> & {
	endpoint: string;
	method?: 'POST' | 'PUT' | 'PATCH' | 'DELETE';
	headers?: Record<string, string>;
	authRequired?: boolean;
};

export function useTypedMutation<TRequest, TResponse>(
	options: TypedMutationOptions<TRequest, TResponse>,
): UseMutationResult<SafeApiResponse<TResponse>, never, TRequest> {
	const {
		endpoint,
		method = 'POST',
		headers = {},
		authRequired = true,
		...mutationOptions
	} = options;

	return useMutation<SafeApiResponse<TResponse>, never, TRequest>({
		mutationFn: async (data: TRequest): Promise<SafeApiResponse<TResponse>> => {
			try {
				const requestBody = data;

				const requestHeaders: Record<string, string> = {
					'Content-Type': 'application/json',
					...headers,
				};

				// Add auth header if required
				if (authRequired) {
					const token = await getSessionToken();
					if (token) {
						requestHeaders['Authorization'] = `Bearer ${token}`;
					}
				}

				const response = await fetch(
					`${process.env['BACKEND_BASE_URL']}${endpoint}`,
					{
						method,
						headers: requestHeaders,
						body: JSON.stringify(requestBody),
					},
				);

				const responseData: unknown = await response.json();
				if (!response.ok) {
					// Type guard for error response
					const {error} = responseData as BackendResponse<null>;
					return {
						data: null,
						error: error || {
							code: 'UNKNOWN_ERROR',
							message: 'An error occurred',
							statusCode: 500,
						},
						message: error?.message || 'An error occurred',
					};
				}

				// Type guard for successful response with data property
				if (
					responseData &&
					typeof responseData === 'object' &&
					'data' in responseData
				) {
					const apiResponse = responseData as {
						data: unknown;
						error?: BackendError | null;
						message?: string;
					};

					return {
						data: apiResponse.data as TResponse,
						error: apiResponse.error || null,
						message: apiResponse.message || 'Success',
					};
				} else {
					return {
						data: responseData as TResponse,
						error: null,
						message: 'Success',
					};
				}
			} catch (error) {
				// Network error or parsing error
				const errorMessage =
					error instanceof Error
						? {
								code: 'UNKNOWN_ERROR',
								message: error.message,
								statusCode: 500,
							}
						: {
								code: 'UNKNOWN_ERROR',
								message: 'Unknown error occurred',
								statusCode: 500,
							};

				return {
					data: null,
					error: errorMessage,
					message: 'An error occurred',
				};
			}
		},
		...mutationOptions,
	});
}
