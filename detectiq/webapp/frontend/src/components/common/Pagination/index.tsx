import { Box, Pagination as MuiPagination } from '@mui/material';

interface PaginationProps {
  totalPages: number;
  currentPage: number;
  onChange: (event: React.ChangeEvent<unknown>, value: number) => void;
}

export default function Pagination({ totalPages, currentPage, onChange }: PaginationProps) {
  if (totalPages <= 1) return null;

  return (
    <Box sx={{ display: 'flex', justifyContent: 'center', mt: 4, mb: 4 }}>
      <MuiPagination
        count={totalPages}
        page={currentPage}
        onChange={onChange}
        color="primary"
        showFirstButton
        showLastButton
      />
    </Box>
  );
} 