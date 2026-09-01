const express = require('express');
const router = express.Router();
const db = require('../db');
const { ensurePremium } = require('../middlewares/premiumAccess');
const { getAllUserStats } = require('../utils/userStats');
const CacheService = require('../services/cacheService');

// Apply premium middleware to all routes (Temporarily disabled for crossword testing)
// router.use(ensurePremium);



// Premium Vocabulary Export
router.get('/vocab/export', async (req, res) => {
  try {
    const userId = req.user.id;
    
    const vocabularyResult = await db.query(`
      SELECT word, definition, dateAdded, correctCount
      FROM vocabulary 
      WHERE userId = $1 
      ORDER BY dateAdded DESC
    `, [userId]);
    const vocabulary = vocabularyResult.rows;
    
    // Create CSV content
    const csvContent = [
      'Word,Definition,Date Added,Mastery Level',
      ...vocabulary.map(v => 
        `"${v.word}","${v.definition}","${v.dateadded}","${v.correctcount >= 5 ? 'Mastered' : v.correctcount > 0 ? 'Learning' : 'New'}"`
      )
    ].join('\n');
    
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="snowwords-vocabulary.csv"');
    res.send(csvContent);
  } catch (error) {
    console.error('Export error:', error);
    res.status(500).json({ error: 'Failed to export vocabulary' });
  }
});

// Premium Study Reminders
router.post('/reminders', async (req, res) => {
  try {
    const userId = req.user.id;
    const { time, frequency, enabled } = req.body;
    
    // Save reminder preferences (PostgreSQL UPSERT)
    await db.query(`
      INSERT INTO study_reminders (userId, time, frequency, enabled)
      VALUES ($1, $2, $3, $4)
      ON CONFLICT (userId) 
      DO UPDATE SET 
        time = EXCLUDED.time,
        frequency = EXCLUDED.frequency,
        enabled = EXCLUDED.enabled,
        dateCreated = CURRENT_TIMESTAMP
    `, [userId, time, frequency, enabled]);
    
    res.json({ success: true, message: 'Reminder settings saved' });
  } catch (error) {
    console.error('Reminder error:', error);
    res.status(500).json({ error: 'Failed to save reminder settings' });
  }
});

// Premium Study Goals
router.post('/goals', async (req, res) => {
  try {
    const userId = req.user.id;
    const { dailyWords, weeklyHours, targetDate } = req.body;
    
    // Save study goals (PostgreSQL UPSERT)
    await db.query(`
      INSERT INTO study_goals (userId, dailyWords, weeklyHours, targetDate)
      VALUES ($1, $2, $3, $4)
      ON CONFLICT (userId) 
      DO UPDATE SET 
        dailyWords = EXCLUDED.dailyWords,
        weeklyHours = EXCLUDED.weeklyHours,
        targetDate = EXCLUDED.targetDate,
        dateCreated = CURRENT_TIMESTAMP
    `, [userId, dailyWords, weeklyHours, targetDate]);
    
    res.json({ success: true, message: 'Study goals saved' });
  } catch (error) {
    console.error('Goals error:', error);
    res.status(500).json({ error: 'Failed to save study goals' });
  }
});

// Crossword Puzzle Generation (Free: 1/day, Premium: unlimited)
router.post('/crossword/generate', async (req, res) => {
  try {
    const userId = req.user.id;
    const isPremium = req.user.subscriptionstatus === 'premium';
    console.log('Generating crossword for user:', userId, 'Premium:', isPremium);

    // Check daily limit for free users
    if (!isPremium) {
      const userResult = await db.query(
        'SELECT "lastCrosswordDate" FROM users WHERE id = $1',
        [userId]
      );

      const lastCrosswordDate = userResult.rows[0]?.lastCrosswordDate;
      const today = new Date().toDateString();

      if (lastCrosswordDate && new Date(lastCrosswordDate).toDateString() === today) {
        return res.status(429).json({
          error: 'Daily crossword limit reached. Premium users get unlimited crosswords!',
          limitReached: true
        });
      }
    }

    // Get user's vocabulary words
    const vocabResult = await db.query(`
      SELECT word, definition
      FROM vocabulary
      WHERE userId = $1
      AND LENGTH(word) >= 3
      ORDER BY RANDOM()
      LIMIT 15
    `, [userId]);

    console.log('Retrieved vocabulary count:', vocabResult.rows.length);

    if (vocabResult.rows.length < 5) {
      return res.status(400).json({
        error: 'You need at least 5 words in your vocabulary to generate a crossword puzzle'
      });
    }

    const words = vocabResult.rows;
    console.log('Generating crossword with words:', words.map(w => w.word));

    const crossword = generateCrossword(words);
    console.log('Crossword generated successfully');

    // Update last crossword date for free users
    if (!isPremium) {
      await db.query(
        'UPDATE users SET "lastCrosswordDate" = NOW() WHERE id = $1',
        [userId]
      );
    }

    res.json(crossword);
  } catch (error) {
    console.error('Crossword generation error:', error);
    res.status(500).json({ error: 'Failed to generate crossword puzzle' });
  }
});



// Helper function to generate crossword puzzle
function generateCrossword(words) {
  try {
    const size = 15; // 15x15 grid
    const grid = Array(size).fill().map(() => Array(size).fill(''));
    const placedWords = [];

    console.log('Starting crossword generation with', words.length, 'words');

    // Sort words by length (longest first) for better placement
    words.sort((a, b) => b.word.length - a.word.length);

    // Place first word in the center
    const firstWord = words[0];
    const startRow = Math.floor(size / 2);
    const startCol = Math.floor((size - firstWord.word.length) / 2);

    console.log('Placing first word:', firstWord.word, 'at', startRow, startCol);

    placeWord(grid, firstWord, startRow, startCol, 'across');
    placedWords.push({
      word: firstWord.word.toUpperCase(),
      row: startRow,
      col: startCol,
      direction: 'across',
      definition: firstWord.definition
    });

    // Try to place remaining words by intersecting with already-placed ones
    for (let i = 1; i < words.length; i++) {
      const word = words[i];
      console.log(`Attempting to place word ${i}: "${word.word}"`);

      const placed = tryPlaceWord(grid, word, placedWords);

      if (placed) {
        placed.definition = word.definition;
        placedWords.push(placed);
        console.log(`✓ Successfully placed "${word.word}" ${placed.direction} at (${placed.row}, ${placed.col})`);
      } else {
        console.log(`✗ Could not place "${word.word}"`);
      }
    }

    console.log('Placed', placedWords.length, 'words out of', words.length);

    // Assign clue numbers using the standard crossword convention: number the
    // unique starting cells in reading order (top-to-bottom, left-to-right).
    // An across word and a down word that begin on the same cell share a number.
    const startKeys = [...new Set(placedWords.map(p => `${p.row},${p.col}`))]
      .map(k => {
        const [r, c] = k.split(',').map(Number);
        return { r, c };
      })
      .sort((a, b) => (a.r - b.r) || (a.c - b.c));

    const numberMap = new Map();
    startKeys.forEach((cell, idx) => numberMap.set(`${cell.r},${cell.c}`, idx + 1));

    const clues = { across: [], down: [] };
    for (const placed of placedWords) {
      placed.number = numberMap.get(`${placed.row},${placed.col}`);
      const entry = {
        number: placed.number,
        clue: placed.definition,
        answer: placed.word.toUpperCase()
      };
      if (placed.direction === 'across') {
        clues.across.push(entry);
      } else {
        clues.down.push(entry);
      }
    }
    clues.across.sort((a, b) => a.number - b.number);
    clues.down.sort((a, b) => a.number - b.number);

    // Fill empty cells with black squares
    for (let row = 0; row < size; row++) {
      for (let col = 0; col < size; col++) {
        if (grid[row][col] === '') {
          grid[row][col] = '#';
        }
      }
    }
    
    // Add numbers to cells
    const numberedGrid = addNumbers(grid, placedWords);
    
    console.log('Crossword generation completed successfully');
    
    return {
      size,
      grid: numberedGrid,
      clues,
      placedWords
    };
  } catch (error) {
    console.error('Error in generateCrossword function:', error);
    throw error;
  }
}

function placeWord(grid, word, row, col, direction) {
  const wordUpper = word.word.toUpperCase();
  
  for (let i = 0; i < wordUpper.length; i++) {
    if (direction === 'across') {
      grid[row][col + i] = wordUpper[i];
    } else {
      grid[row + i][col] = wordUpper[i];
    }
  }
}

function tryPlaceWord(grid, word, placedWords) {
  const wordUpper = word.word.toUpperCase();
  let attemptCount = 0;

  for (const placed of placedWords) {
    // Try to intersect with each placed word
    for (let i = 0; i < wordUpper.length; i++) {
      for (let j = 0; j < placed.word.length; j++) {
        if (wordUpper[i] === placed.word[j].toUpperCase()) {
          attemptCount++;

          // Determine which direction to try based on placed word's direction
          // If placed word is across, try placing new word down and vice versa
          const newDirection = placed.direction === 'across' ? 'down' : 'across';

          const result = tryIntersection(grid, wordUpper, placed, i, j, newDirection);
          if (result) {
            console.log(`  Found intersection: "${wordUpper[i]}" matches "${placed.word[j]}" in "${placed.word}"`);
            return result;
          }
        }
      }
    }
  }

  console.log(`  Tried ${attemptCount} potential intersections, none valid`);
  return null;
}

function tryIntersection(grid, word, placed, wordIndex, placedIndex, direction) {
  const size = grid.length;

  // Only allow perpendicular intersections (across with down, or down with across)
  if (direction === placed.direction) {
    return null; // Can't intersect two words going in the same direction
  }

  // Calculate position for new word based on intersection point
  let newRow, newCol;

  if (direction === 'across') {
    // New word going across, intersecting with a word going down
    // The intersection point is at (placed.row + placedIndex, placed.col)
    newRow = placed.row + placedIndex;
    newCol = placed.col - wordIndex;
  } else {
    // New word going down, intersecting with a word going across
    // The intersection point is at (placed.row, placed.col + placedIndex)
    newRow = placed.row - wordIndex;
    newCol = placed.col + placedIndex;
  }

  // Check if placement is valid
  if (isValidPlacement(grid, word, newRow, newCol, direction)) {
    placeWord(grid, { word }, newRow, newCol, direction);
    return {
      word,
      row: newRow,
      col: newCol,
      direction
    };
  } else {
    console.log(`    Placement invalid at (${newRow}, ${newCol}) ${direction}`);
  }

  return null;
}

function isValidPlacement(grid, word, row, col, direction) {
  const size = grid.length;

  // Check bounds
  if (direction === 'across') {
    if (col < 0 || col + word.length > size || row < 0 || row >= size) {
      return false;
    }
  } else {
    if (row < 0 || row + word.length > size || col < 0 || col >= size) {
      return false;
    }
  }

  // Check each cell position
  for (let i = 0; i < word.length; i++) {
    let cellRow = row, cellCol = col;
    if (direction === 'across') {
      cellCol = col + i;
    } else {
      cellRow = row + i;
    }

    const currentCell = grid[cellRow][cellCol];

    // If cell is occupied, it must match exactly (valid intersection)
    if (currentCell !== '' && currentCell !== word[i]) {
      return false;
    }

    // For a brand-new letter (not an intersection), the perpendicular
    // neighbours must be empty. Otherwise the new word would run directly
    // alongside an existing word and create invalid, unintended entries.
    if (currentCell === '') {
      if (direction === 'across') {
        if (cellRow > 0 && grid[cellRow - 1][cellCol] !== '') return false;
        if (cellRow < size - 1 && grid[cellRow + 1][cellCol] !== '') return false;
      } else {
        if (cellCol > 0 && grid[cellRow][cellCol - 1] !== '') return false;
        if (cellCol < size - 1 && grid[cellRow][cellCol + 1] !== '') return false;
      }
    }
  }

  // Check cells immediately before and after the word to ensure proper separation
  if (direction === 'across') {
    // Check cell before the word
    if (col > 0) {
      const before = grid[row][col - 1];
      if (before !== '' && before !== '#') {
        return false;
      }
    }
    // Check cell after the word
    if (col + word.length < size) {
      const after = grid[row][col + word.length];
      if (after !== '' && after !== '#') {
        return false;
      }
    }
  } else {
    // Check cell before the word
    if (row > 0) {
      const before = grid[row - 1][col];
      if (before !== '' && before !== '#') {
        return false;
      }
    }
    // Check cell after the word
    if (row + word.length < size) {
      const after = grid[row + word.length][col];
      if (after !== '' && after !== '#') {
        return false;
      }
    }
  }

  return true;
}

function getAdjacentCells(grid, row, col) {
  const adjacent = [];
  const directions = [[-1, 0], [1, 0], [0, -1], [0, 1]];
  
  for (const [dr, dc] of directions) {
    const newRow = row + dr;
    const newCol = col + dc;
    if (newRow >= 0 && newRow < grid.length && newCol >= 0 && newCol < grid[0].length) {
      adjacent.push(grid[newRow][newCol]);
    }
  }
  
  return adjacent;
}

function addNumbers(grid, placedWords) {
  const numberedGrid = grid.map(row => row.map(cell => ({ value: cell })));
  const cellNumbers = new Map(); // Track which numbers start at which cells

  for (const placed of placedWords) {
    const number = placed.number;
    const row = placed.row;
    const col = placed.col;
    const wordLength = placed.word.length;

    // Ensure row and col are valid
    if (row === undefined || col === undefined || row < 0 || col < 0 ||
        row >= numberedGrid.length || col >= numberedGrid[0].length) {
      continue;
    }

    // Set number on the first cell only
    const cellKey = `${row},${col}`;
    if (!cellNumbers.has(cellKey)) {
      numberedGrid[row][col].number = number;
      cellNumbers.set(cellKey, number);
    }

    // Set direction attribute on ALL cells of the word
    for (let i = 0; i < wordLength; i++) {
      let cellRow = row;
      let cellCol = col;

      if (placed.direction === 'across') {
        cellCol = col + i;
      } else {
        cellRow = row + i;
      }

      // Validate cell position
      if (cellRow >= 0 && cellRow < numberedGrid.length &&
          cellCol >= 0 && cellCol < numberedGrid[0].length) {

        if (placed.direction === 'across') {
          numberedGrid[cellRow][cellCol].across = number;
        } else {
          numberedGrid[cellRow][cellCol].down = number;
        }
      }
    }
  }

  return numberedGrid;
}

module.exports = router;
