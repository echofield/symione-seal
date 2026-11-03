import { createApp, type Env } from './app';

export default {
  fetch(request: Request, env: Env): Promise<Response> {
    return createApp(env).fetch(request);
  },
} satisfies ExportedHandler<Env>;
