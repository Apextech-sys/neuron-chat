import { requesty } from '@requesty/ai-sdk';

export const customModel = () => {
  return requesty('openai/gpt-5-mini');
};
