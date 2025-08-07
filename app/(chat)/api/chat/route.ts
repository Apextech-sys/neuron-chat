import {
  convertToCoreMessages,
  CoreMessage,
  Message,
  StreamData,
  streamObject,
  streamText,
} from 'ai';
import { z } from 'zod';

import { customModel } from '@/ai';
import { systemPrompt } from '@/ai/prompts';
import { getChatById, getDocumentById, getSession } from '@/db/cached-queries';
import {
  saveChat,
  saveDocument,
  saveMessages,
  saveSuggestions,
} from '@/db/mutations';
import { createClient } from '@/lib/supabase/server';
import { MessageRole } from '@/lib/supabase/types';
import {
  generateUUID,
  getMostRecentUserMessage,
  sanitizeResponseMessages,
} from '@/lib/utils';

import { generateTitleFromUserMessage } from '../../actions';

export const maxDuration = 60;

type AllowedTools =
  | 'createDocument'
  | 'updateDocument'
  | 'requestSuggestions'
  | 'getWeather';

const blocksTools: AllowedTools[] = [
  'createDocument',
  'updateDocument',
  'requestSuggestions',
];

const weatherTools: AllowedTools[] = ['getWeather'];

const allTools: AllowedTools[] = [...blocksTools, ...weatherTools];

async function getUser() {
  const supabase = await createClient();
  const {
    data: { user },
    error,
  } = await supabase.auth.getUser();

  if (error || !user) {
    throw new Error('Unauthorized');
  }

  return user;
}

// Add helper function to format message content for database storage
function formatMessageContent(message: CoreMessage): string {
  // For user messages, store as plain text
  if (message.role === 'user') {
    return typeof message.content === 'string'
      ? message.content
      : JSON.stringify(message.content);
  }

  // For tool messages, format as array of tool results
  if (message.role === 'tool') {
    return JSON.stringify(
      message.content.map((content) => ({
        type: content.type || 'tool-result',
        toolCallId: content.toolCallId,
        toolName: content.toolName,
        result: content.result,
      }))
    );
  }

  // For assistant messages, format as array of text and tool calls
  if (message.role === 'assistant') {
    if (typeof message.content === 'string') {
      return JSON.stringify([{ type: 'text', text: message.content }]);
    }

    return JSON.stringify(
      message.content.map((content) => {
        if (content.type === 'text') {
          return {
            type: 'text',
            text: content.text,
          };
        }
        if (content.type === 'tool-call') {
          return {
            type: 'tool-call',
            toolCallId: (content as any).toolCallId,
            toolName: (content as any).toolName,
            args: (content as any).args,
          };
        }
        return content;
      })
    );
  }

  return '';
}

export async function POST(request: Request) {
  const {
    id,
    messages,
  }: { id: string; messages: Array<Message> } =
    await request.json();

  const user = await getUser();

  if (!user) {
    return new Response('Unauthorized', { status: 401 });
  }

  const coreMessages = convertToCoreMessages(messages);
  const userMessage = getMostRecentUserMessage(coreMessages);

  if (!userMessage) {
    return new Response('No user message found', { status: 400 });
  }

  // Get the original message with ID from the messages array
  const originalUserMessage = messages[messages.length - 1];
  
  // Debug logging to see what we're getting
  console.log('Original user message:', JSON.stringify(originalUserMessage, null, 2));
  console.log('Message ID:', originalUserMessage?.id);

  try {
    const chat = await getChatById(id);

    if (!chat) {
      const title = await generateTitleFromUserMessage({
        message: userMessage,
      });
      await saveChat({ id, userId: user.id, title });
    } else if (chat.user_id !== user.id) {
      return new Response('Unauthorized', { status: 401 });
    }

    await saveMessages({
      chatId: id,
      messages: [
        {
          id: originalUserMessage?.id || generateUUID(), // Use original ID or generate one
          chat_id: id,
          role: userMessage.role as MessageRole,
          content: formatMessageContent(userMessage),
          created_at: new Date().toISOString(),
        },
      ],
    });

    const streamingData = new StreamData();

    const result = await streamText({
      model: customModel(),
      system: systemPrompt,
      messages: coreMessages,
      maxSteps: 5,
      experimental_activeTools: allTools,
      tools: {
        getWeather: {
          description: 'Get the current weather at a location',
          parameters: z.object({
            latitude: z.number(),
            longitude: z.number(),
          }),
          execute: async ({ latitude, longitude }) => {
            const response = await fetch(
              `https://api.open-meteo.com/v1/forecast?latitude=${latitude}&longitude=${longitude}&current=temperature_2m&hourly=temperature_2m&daily=sunrise,sunset&timezone=auto`
            );

            const weatherData = await response.json();
            return weatherData;
          },
        },
        createDocument: {
          description: 'Create a document for a writing activity',
          parameters: z.object({
            title: z.string(),
          }),
          execute: async ({ title }) => {
            const id = generateUUID();
            let draftText: string = '';

            // Stream UI updates immediately for better UX
            streamingData.append({ type: 'id', content: id });
            streamingData.append({ type: 'title', content: title });
            streamingData.append({ type: 'clear', content: '' });

            // Generate content
            const { fullStream } = await streamText({
              model: customModel(),
              system:
                'Write about the given topic. Markdown is supported. Use headings wherever appropriate.',
              prompt: title,
            });

            for await (const delta of fullStream) {
              const { type } = delta;

              if (type === 'text-delta') {
                draftText += delta.textDelta;
                // Stream content updates in real-time
                streamingData.append({
                  type: 'text-delta',
                  content: delta.textDelta,
                });
              }
            }

            // Try to save with retries
            // let attempts = 0;
            // const maxAttempts = 3;
            // let savedId: string | null = null;

            // while (attempts < maxAttempts && !savedId) {
            //   try {
            //     await saveDocument({
            //       id,
            //       title,
            //       content: draftText,
            //       userId: user.id,
            //     });
            //     savedId = id;
            //     break;
            //   } catch (error) {
            //     attempts++;
            //     if (attempts === maxAttempts) {
            //       // If original ID fails, try with a new ID
            //       const newId = generateUUID();
            //       try {
            //         await saveDocument({
            //           id: newId,
            //           title,
            //           content: draftText,
            //           userId: user.id,
            //         });
            //         // Update the ID in the UI
            //         streamingData.append({ type: 'id', content: newId });
            //         savedId = newId;
            //       } catch (finalError) {
            //         console.error('Final attempt failed:', finalError);
            //         return {
            //           error:
            //             'Failed to create document after multiple attempts',
            //         };
            //       }
            //     }
            //     await new Promise((resolve) =>
            //       setTimeout(resolve, 100 * attempts)
            //     );
            //   }
            // }

            streamingData.append({ type: 'finish', content: '' });

            if (user && user.id) {
              await saveDocument({
                id,
                title,
                content: draftText,
                userId: user.id,
              });
            }

            return {
              id,
              title,
              content: `A document was created and is now visible to the user.`,
            };
          },
        },
        updateDocument: {
          description: 'Update a document with the given description',
          parameters: z.object({
            id: z.string().describe('The ID of the document to update'),
            description: z
              .string()
              .describe('The description of changes that need to be made'),
          }),
          execute: async ({ id, description }) => {
            const document = await getDocumentById(id);

            if (!document) {
              return {
                error: 'Document not found',
              };
            }

            const { content: currentContent } = document;
            let draftText: string = '';

            streamingData.append({
              type: 'clear',
              content: document.title,
            });

            const { fullStream } = await streamText({
              model: customModel(),
              system:
                'You are a helpful writing assistant. Based on the description, please update the piece of writing.',
              experimental_providerMetadata: {
                openai: {
                  prediction: {
                    type: 'content',
                    content: currentContent,
                  },
                },
              },
              messages: [
                {
                  role: 'user',
                  content: description,
                },
                { role: 'user', content: currentContent },
              ],
            });

            for await (const delta of fullStream) {
              const { type } = delta;

              if (type === 'text-delta') {
                const { textDelta } = delta;

                draftText += textDelta;
                streamingData.append({
                  type: 'text-delta',
                  content: textDelta,
                });
              }
            }

            streamingData.append({ type: 'finish', content: '' });

            if (user && user.id) {
              await saveDocument({
                id,
                title: document.title,
                content: draftText,
                userId: user.id,
              });
            }

            return {
              id,
              title: document.title,
              content: 'The document has been updated successfully.',
            };
          },
        },
        requestSuggestions: {
          description: 'Request suggestions for a document',
          parameters: z.object({
            documentId: z
              .string()
              .describe('The ID of the document to request edits'),
          }),
          execute: async ({ documentId }) => {
            const document = await getDocumentById(documentId);

            if (!document || !document.content) {
              return {
                error: 'Document not found',
              };
            }

            let suggestions: Array<{
              originalText: string;
              suggestedText: string;
              description: string;
              id: string;
              documentId: string;
              isResolved: boolean;
            }> = [];

            const { elementStream } = await streamObject({
              model: customModel(),
              system:
                'You are a help writing assistant. Given a piece of writing, please offer suggestions to improve the piece of writing and describe the change. It is very important for the edits to contain full sentences instead of just words. Max 5 suggestions.',
              prompt: document.content,
              output: 'array',
              schema: z.object({
                originalSentence: z.string().describe('The original sentence'),
                suggestedSentence: z
                  .string()
                  .describe('The suggested sentence'),
                description: z
                  .string()
                  .describe('The description of the suggestion'),
              }),
            });

            for await (const element of elementStream) {
              const suggestion = {
                originalText: element.originalSentence,
                suggestedText: element.suggestedSentence,
                description: element.description,
                id: generateUUID(),
                documentId: documentId,
                isResolved: false,
              };

              streamingData.append({
                type: 'suggestion',
                content: suggestion,
              });

              suggestions.push(suggestion);
            }

            if (user && user.id) {
              const userId = user.id;

              await saveSuggestions({
                suggestions: suggestions.map((suggestion) => ({
                  ...suggestion,
                  userId,
                  createdAt: new Date(),
                  documentCreatedAt: document.created_at,
                })),
              });
            }

            // if (user && user.id) {
            //   for (const suggestion of suggestions) {
            //     await saveSuggestions({
            //       documentId: suggestion.documentId,
            //       documentCreatedAt: document.created_at,
            //       originalText: suggestion.originalText,
            //       suggestedText: suggestion.suggestedText,
            //       description: suggestion.description,
            //       userId: user.id,
            //     });
            //   }
            // }

            return {
              id: documentId,
              title: document.title,
              message: 'Suggestions have been added to the document',
            };
          },
        },
      },
      onFinish: async (result) => {
        if (user && user.id) {
          try {
            // Save the assistant's response message - generate ID since result.response.id doesn't exist
            const assistantMessage = {
              id: generateUUID(), // Generate a proper ID for the assistant message
              chat_id: id,
              role: 'assistant' as MessageRole,
              content: result.text || '',
              created_at: new Date().toISOString(),
            };

            await saveMessages({
              chatId: id,
              messages: [assistantMessage],
            });

            console.log('Chat completed successfully');
          } catch (error) {
            console.error('Failed to save chat:', error);
          }
        }

        streamingData.close();
      },
      experimental_telemetry: {
        isEnabled: true,
        functionId: 'stream-text',
      },
    });

    return result.toDataStreamResponse({
      data: streamingData,
    });
  } catch (error) {
    console.error('Error in chat route:', error);
    if (error instanceof Error && error.message === 'Chat ID already exists') {
      // Chat already exists, skip chat creation and just save the user message
      console.log('Chat already exists, continuing with message saving...');
      // The main flow will continue and handle the user message and streaming
    } else {
      return new Response('An error occurred while processing your request', {
        status: 500,
      });
    }
  }

  // Continue with normal flow (this runs whether chat was new or already existed)
  try {
    await saveMessages({
      chatId: id,
      messages: [
        {
          id: originalUserMessage?.id || generateUUID(), // Use original ID or generate one
          chat_id: id,
          role: userMessage.role as MessageRole,
          content: formatMessageContent(userMessage),
          created_at: new Date().toISOString(),
        },
      ],
    });
  } catch (saveError) {
    console.error('Failed to save user message:', saveError);
    return new Response('Failed to save message', { status: 500 });
  }

  const streamingData = new StreamData();

  const result = await streamText({
    model: customModel(),
    system: systemPrompt,
    messages: coreMessages,
    maxSteps: 5,
    experimental_activeTools: ['getWeather'],
    tools: {
      getWeather: {
        description: 'Get the current weather at a location',
        parameters: z.object({
          latitude: z.number(),
          longitude: z.number(),
        }),
        execute: async ({ latitude, longitude }) => {
          const response = await fetch(
            `https://api.open-meteo.com/v1/forecast?latitude=${latitude}&longitude=${longitude}&current=temperature_2m&hourly=temperature_2m&daily=sunrise,sunset&timezone=auto`
          );
          const weatherData = await response.json();
          return weatherData;
        },
      },
    },
    onFinish: async (result) => {
      if (user && user.id) {
        try {
          const assistantMessage = {
            id: generateUUID(),
            chat_id: id,
            role: 'assistant' as MessageRole,
            content: result.text || '',
            created_at: new Date().toISOString(),
          };

          await saveMessages({
            chatId: id,
            messages: [assistantMessage],
          });

          console.log('Chat completed successfully');
        } catch (error) {
          console.error('Failed to save assistant message:', error);
        }
      }
      streamingData.close();
    },
  });

  return result.toDataStreamResponse({ data: streamingData });
}

