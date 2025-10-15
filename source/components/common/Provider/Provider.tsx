'use client';

import type React from 'react';

// hooks

// components
import {QueryClient, QueryClientProvider} from '@tanstack/react-query';
import {useState} from 'react';

interface Props {
	children: React.ReactNode;
}

export const Provider: React.FC<Props> = ({children}) => {
	const [queryClient] = useState(
		() =>
			new QueryClient({
				defaultOptions: {
					queries: {
						staleTime: 60 * 1000,
						gcTime: 10 * 60 * 1000,
						refetchOnWindowFocus: false,
						retry: (failureCount, error: unknown) => {
							const hasStatus = (err: unknown): err is {status: number} => {
								return (
									typeof err === 'object' && err !== null && 'status' in err
								);
							};

							if (
								hasStatus(error) &&
								error.status >= 400 &&
								error.status < 500
							) {
								return false;
							}
							return failureCount < 3;
						},
					},
					mutations: {
						retry: 1,
					},
				},
			}),
	);

	return (
		<QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
	);
};
