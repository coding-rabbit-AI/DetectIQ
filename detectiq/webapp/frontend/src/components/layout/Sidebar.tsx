'use client';

import { List, ListItem, ListItemIcon, ListItemText } from '@mui/material';
import SecurityIcon from '@mui/icons-material/Security';
import SettingsIcon from '@mui/icons-material/Settings';
import BuildIcon from '@mui/icons-material/Build';
import InfoIcon from '@mui/icons-material/Info';
import { usePathname, useRouter } from 'next/navigation';

const menuItems = [
  { text: 'Rules', icon: <SecurityIcon />, path: '/' },
  { text: 'Rule Creator', icon: <BuildIcon />, path: '/rule-creator' },
  { text: 'Settings', icon: <SettingsIcon />, path: '/settings' },
  { text: 'About', icon: <InfoIcon />, path: '/about' },
];

const cardHoverStyle = {
  transition: 'transform 0.2s ease-in-out, box-shadow 0.2s ease-in-out',
  '&:hover': {
    transform: 'translateY(-4px)',
    boxShadow: '0 4px 20px rgba(0,0,0,0.12)',
  }
};

export default function Sidebar() {
  const router = useRouter();
  const pathname = usePathname();

  const isSelected = (itemPath: string) => {
    if (itemPath === '/') {
      return pathname === '/';
    }
    return pathname.startsWith(itemPath);
  };

  return (
    <List sx={{ pt: 2 }}>
      {menuItems.map((item) => (
        <ListItem
          key={item.text}
          onClick={() => router.push(item.path)}
          sx={{
            mb: 1.5,
            mx: 2,
            borderRadius: 2,
            cursor: 'pointer',
            transition: 'all 0.2s ease-in-out',
            bgcolor: isSelected(item.path) ? 'rgba(97, 84, 163, 0.15)' : 'transparent',
            '&:hover': {
              bgcolor: 'rgba(97, 84, 163, 0.1)',
              transform: 'translateX(4px)',
            },
            '& .MuiListItemIcon-root': {
              color: isSelected(item.path) ? '#6154a3' : 'inherit',
              transition: 'color 0.2s ease-in-out',
            },
            '& .MuiListItemText-primary': {
              fontWeight: isSelected(item.path) ? 600 : 400,
              color: isSelected(item.path) ? '#6154a3' : 'inherit',
            }
          }}
        >
          <ListItemIcon 
            sx={{ 
              color: isSelected(item.path) ? 'primary.light' : 'inherit',
              minWidth: 40 
            }}
          >
            {item.icon}
          </ListItemIcon>
          <ListItemText 
            primary={item.text}
            primaryTypographyProps={{
              fontSize: '0.95rem',
              fontWeight: isSelected(item.path) ? 600 : 400,
            }}
          />
        </ListItem>
      ))}
    </List>
  );
} 