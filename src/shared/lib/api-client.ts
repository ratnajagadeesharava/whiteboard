const BASE_URL = "http://localhost:8080/api";

interface RequestConfig extends RequestInit {
  token?: string;
}

export async function apiClient<T>(
  endpoint: string,
  config: RequestConfig = {},
): Promise<T> {
  const { token, headers, ...rest } = config;
  const response = await fetch(`${BASE_URL}${endpoint}`, {
    ...rest,
    headers: {
      "Content-Type": "application/json",
      ...(token && {
        Authorization: `Bearer ${token}`,
      }),
      ...headers
    },
  });
  if(!response.ok){
    throw new Error("Request Failed")
  }
  return response.json();
}
