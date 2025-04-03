<?php
session_start();
include 'db.php';

// Initialize session posts if not exists
if (!isset($_SESSION['posts'])) {
    $_SESSION['posts'] = [];
}

// Define cooldown period (in seconds)
$cooldownPeriod = 30; // Adjust this as needed

// Handle new post
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['content'])) {
    if (isset($_SESSION['user_id'])) {
        $stmt = $pdo->prepare("SELECT name FROM profiles WHERE id = ?");
        $stmt->execute([$_SESSION['user_id']]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        $currentTime = time();
        $content = trim($_POST['content']);

        // Initialize session variables for rate limiting if not set
        if (!isset($_SESSION['last_post_time'])) {
            $_SESSION['last_post_time'] = 0;
        }
        if (!isset($_SESSION['last_post_content'])) {
            $_SESSION['last_post_content'] = '';
        }

        // Check cooldown
        $timeSinceLastPost = $currentTime - $_SESSION['last_post_time'];
        if ($timeSinceLastPost < $cooldownPeriod) {
            $error = "Please wait " . ($cooldownPeriod - $timeSinceLastPost) . " seconds before posting again.";
        }
        // Check for duplicate message
        elseif ($content === $_SESSION['last_post_content']) {
            $error = "You cannot post the same message twice in a row.";
        }
        // If no issues, process the post
        elseif (!empty($content)) {
            $_SESSION['posts'][] = [
                'id' => uniqid(),
                'user' => $user['name'],
                'content' => $content,
                'time' => date('H:i')
            ];
            $_SESSION['last_post_time'] = $currentTime;
            $_SESSION['last_post_content'] = $content;
        }
    }
}

$userProfile = null;
if (isset($_SESSION['user_id'])) {
    $stmt = $pdo->prepare("SELECT * FROM profiles WHERE id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    $userProfile = $stmt->fetch(PDO::FETCH_ASSOC);
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Love4Free - Your Spotlight</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    .player-container {
      height: calc(100vh - 4rem);
    }
    .posts-container {
      height: calc(100vh - 8rem);
    }
  </style>
</head>
<body class="bg-gray-900 text-white flex h-screen overflow-hidden">
  <!-- Music Player Sidebar -->
  <div class="w-64 p-4 bg-gray-800 flex flex-col player-container">
    <h2 class="text-xl font-bold mb-4">Now Playing</h2>
    <div id="player-content" class="flex-1">
      <?php if ($userProfile && $userProfile['song']): ?>
        <?php if ($userProfile['song_type'] === 'spotify'): ?>
          <iframe src="https://open.spotify.com/embed/track/<?php echo basename($userProfile['song']); ?>" 
                  width="100%" height="80" frameborder="0" allowtransparency="true" 
                  allow="encrypted-media" class="mb-4"></iframe>
        <?php else: ?>
          <p class="text-gray-300 mb-2"><?php echo $userProfile['song']; ?></p>
        <?php endif; ?>
      <?php else: ?>
        <p class="text-gray-400">No music playing</p>
      <?php endif; ?>
    </div>
    
    <?php if (!$userProfile): ?>
      <a href="create_profile.php" class="mt-auto px-4 py-2 bg-purple-600 rounded hover:bg-purple-700 text-center">
        Create Profile
      </a>
    <?php endif; ?>
  </div>

  <!-- Main Content -->
  <div class="flex-1 flex flex-col">
    <!-- Wall Posts -->
    <div class="flex-1 overflow-y-auto p-4 posts-container">
      <h2 class="text-xl font-bold mb-4">Love4Free Wall</h2>
      <?php if (isset($error)): ?>
        <p class="text-red-500 mb-4"><?php echo $error; ?></p>
      <?php endif; ?>
      <div id="posts">
        <?php foreach (array_reverse($_SESSION['posts']) as $post): ?>
          <div class="p-3 mb-3 bg-gray-700 rounded-lg">
            <div class="flex justify-between items-center">
              <span class="font-semibold text-purple-300"><?php echo $post['user']; ?></span>
              <span class="text-xs text-gray-400"><?php echo $post['time']; ?></span>
            </div>
            <p class="mt-1"><?php echo $post['content']; ?></p>
          </div>
        <?php endforeach; ?>
      </div>
    </div>
    
    <!-- Post Form -->
    <?php if ($userProfile): ?>
      <div class="p-4 border-t border-gray-700">
        <form method="POST" class="flex">
          <input type="text" name="content" placeholder="Share your love..." 
                 class="flex-1 p-2 bg-gray-700 rounded-l focus:outline-none">
          <button type="submit" class="px-4 py-2 bg-purple-600 rounded-r hover:bg-purple-700">
            Post
          </button>
        </form>
      </div>
    <?php endif; ?>
  </div>

  <!-- Right Sidebar - User Profiles -->
  <div class="w-80 p-4 bg-gray-800 overflow-y-auto">
    <h2 class="text-xl font-bold mb-4">Find Your Match</h2>
    <?php if ($userProfile): ?>
      <form method="GET" class="mb-4">
        <input type="text" name="term" placeholder="Search..." 
               class="w-full p-2 bg-gray-700 rounded">
      </form>
      
      <?php
      $query = "SELECT id, name, song, song_type FROM profiles WHERE id != ?";
      $params = [$_SESSION['user_id']];
      
      if (!empty($_GET['term'])) {
          $query .= " AND (name LIKE ? OR bio LIKE ? OR hobbies LIKE ?)";
          $params[] = "%{$_GET['term']}%";
          $params[] = "%{$_GET['term']}%";
          $params[] = "%{$_GET['term']}%";
      }
      
      $stmt = $pdo->prepare($query);
      $stmt->execute($params);
      
      while ($profile = $stmt->fetch(PDO::FETCH_ASSOC)) {
          echo '<div class="mb-3 p-3 bg-gray-700 rounded-lg hover:bg-gray-600 cursor-pointer" 
                     onclick="window.open(\'profile.php?id='.$profile['id'].'\', \'_blank\')">';
          echo '<div class="font-semibold">'.$profile['name'].'</div>';
          if ($profile['song']) {
              echo '<div class="text-xs text-gray-300 mt-1">';
              echo $profile['song_type'] === 'spotify' ? 'Listening on Spotify' : $profile['song'];
              echo '</div>';
          }
          echo '</div>';
      }
      ?>
    <?php else: ?>
      <p class="text-gray-400">Create a profile to search others!</p>
    <?php endif; ?>
  </div>

  <script>
    // Auto-scroll posts to bottom
    const postsContainer = document.getElementById('posts');
    if (postsContainer) {
      postsContainer.scrollTop = postsContainer.scrollHeight;
    }
  </script>
</body>
</html>