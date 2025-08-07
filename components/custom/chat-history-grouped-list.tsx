'use client';

import { isToday, isYesterday, subMonths, subWeeks } from 'date-fns';
import Link from 'next/link';
import { memo } from 'react';

import {
  SidebarGroup,
  SidebarGroupContent,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from '@/components/ui/sidebar';
import { Chat } from '@/lib/supabase/types';


type GroupedChats = {
  today: Chat[];
  yesterday: Chat[];
  lastWeek: Chat[];
  lastMonth: Chat[];
  older: Chat[];
};

// Memoized group header
const GroupHeader = memo(function GroupHeader({ title }: { title: string }) {
  return (
    <div className="px-2 py-1 text-xs text-sidebar-foreground/50 mt-6 first:mt-0">
      {title}
    </div>
  );
});

// Memoized chat item
const ChatItem = memo(function ChatItem({
  chat,
  isActive,
  setOpenMobile,
}: {
  chat: Chat;
  isActive: boolean;
  setOpenMobile: (open: boolean) => void;
}) {
  return (
    <SidebarMenuItem>
      <SidebarMenuButton asChild isActive={isActive}>
        <Link href={`/chat/${chat.id}`} onClick={() => setOpenMobile(false)}>
          <span>{chat.title || 'New Chat'}</span>
        </Link>
      </SidebarMenuButton>
    </SidebarMenuItem>
  );
});

// Group chats by date
function groupChatsByDate(chats: Chat[]): GroupedChats {
  const now = new Date();
  const oneWeekAgo = subWeeks(now, 1);
  const oneMonthAgo = subMonths(now, 1);

  return chats.reduce(
    (groups, chat) => {
      const chatDate = new Date(chat.created_at);

      if (isToday(chatDate)) {
        groups.today.push(chat);
      } else if (isYesterday(chatDate)) {
        groups.yesterday.push(chat);
      } else if (chatDate > oneWeekAgo) {
        groups.lastWeek.push(chat);
      } else if (chatDate > oneMonthAgo) {
        groups.lastMonth.push(chat);
      } else {
        groups.older.push(chat);
      }

      return groups;
    },
    {
      today: [],
      yesterday: [],
      lastWeek: [],
      lastMonth: [],
      older: [],
    } as GroupedChats
  );
}

export function GroupedChatList({
  chats,
  currentChatId,
  setOpenMobile,
}: {
  chats: Chat[];
  currentChatId: string;
  setOpenMobile: (open: boolean) => void;
}) {
  const groupedChats = groupChatsByDate(chats);

  return (
    <SidebarGroup>
      <SidebarGroupContent>
        <SidebarMenu>
          {groupedChats.today.length > 0 && (
            <>
              <GroupHeader title="Today" />
              {groupedChats.today.map((chat) => (
                <ChatItem
                  key={chat.id}
                  chat={chat}
                  isActive={chat.id === currentChatId}
                  setOpenMobile={setOpenMobile}
                />
              ))}
            </>
          )}

          {groupedChats.yesterday.length > 0 && (
            <>
              <GroupHeader title="Yesterday" />
              {groupedChats.yesterday.map((chat) => (
                <ChatItem
                  key={chat.id}
                  chat={chat}
                  isActive={chat.id === currentChatId}
                  setOpenMobile={setOpenMobile}
                />
              ))}
            </>
          )}

          {groupedChats.lastWeek.length > 0 && (
            <>
              <GroupHeader title="Last 7 days" />
              {groupedChats.lastWeek.map((chat) => (
                <ChatItem
                  key={chat.id}
                  chat={chat}
                  isActive={chat.id === currentChatId}
                  setOpenMobile={setOpenMobile}
                />
              ))}
            </>
          )}

          {groupedChats.lastMonth.length > 0 && (
            <>
              <GroupHeader title="Last 30 days" />
              {groupedChats.lastMonth.map((chat) => (
                <ChatItem
                  key={chat.id}
                  chat={chat}
                  isActive={chat.id === currentChatId}
                  setOpenMobile={setOpenMobile}
                />
              ))}
            </>
          )}

          {groupedChats.older.length > 0 && (
            <>
              <GroupHeader title="Older" />
              {groupedChats.older.map((chat) => (
                <ChatItem
                  key={chat.id}
                  chat={chat}
                  isActive={chat.id === currentChatId}
                  setOpenMobile={setOpenMobile}
                />
              ))}
            </>
          )}
        </SidebarMenu>
      </SidebarGroupContent>
    </SidebarGroup>
  );
}
