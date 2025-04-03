<?php
session_start();
include 'db.php';

$profile = null;
$isOwnProfile = false;
if (isset($_GET['id'])) {
    $stmt = $pdo->prepare("SELECT * FROM profiles WHERE id = ?");
    $stmt->execute([$_GET['id']]);
    $profile = $stmt->fetch(PDO::FETCH_ASSOC);
    $isOwnProfile = isset($_SESSION['user_id']) && $profile && $profile['id'] == $_SESSION['user_id'];
}

if ($isOwnProfile && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $bio = $_POST['bio'] ?? '';
    $song = $_POST['song'] ?? '';
    $song_type = $_POST['song_type'] ?? '';
    $personality = $_POST['personality'] ?? '';
    $job = $_POST['job'] ?? '';
    $hobbies = $_POST['hobbies'] ?? '';
    $love = $_POST['love'] ?? '';
    $travel = $_POST['travel'] ?? '';
    $video = $_POST['video'] ?? '';
    $notes = $_POST['notes'] ?? '';
    
    // Process media URLs
    if (!empty($video) && strpos($video, 'youtube.com') !== false) {
        $video = preg_replace(
            "/\s*[a-zA-Z\/\/:\.]*youtube.com\/watch\?v=([a-zA-Z0-9\-_]+)([a-zA-Z0-9\/\*\-\_\?\&\;\%\=\.]*)/i",
            "https://www.youtube.com/embed/$1",
            $video
        );
    }
    
    if (!empty($song) && strpos($song, 'spotify.com') !== false) {
        $song_type = 'spotify';
        $song = basename(parse_url($song, PHP_URL_PATH));
    }

    $stmt = $pdo->prepare("UPDATE profiles SET bio = ?, song = ?, song_type = ?, personality = ?, job = ?, hobbies = ?, love = ?, travel = ?, video = ?, notes = ? WHERE id = ?");
    $stmt->execute([$bio, $song, $song_type, $personality, $job, $hobbies, $love, $travel, $video, $notes, $_SESSION['user_id']]);
    header("Location: profile.php?id=" . $_SESSION['user_id']);
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title><?php echo $profile ? $profile['name'] . "'s Profile" : 'Profile Not Found'; ?> - Love4Free</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-900 text-white min-h-screen">
  <div class="container mx-auto p-4">
    <?php if ($profile): ?>
      <div class="flex flex-col lg:flex-row gap-6">
        <!-- Main Profile Info -->
        <div class="lg:w-2/3">
          <div class="bg-gray-800 p-6 rounded-lg">
            <h1 class="text-3xl font-bold mb-4"><?php echo $profile['name']; ?></h1>
            
            <?php if ($isOwnProfile): ?>
              <form method="POST" class="space-y-4">
                <div>
                  <label class="block mb-2 font-medium">Bio</label>
                  <textarea name="bio" class="w-full p-3 bg-gray-700 rounded"><?php echo htmlspecialchars($profile['bio']); ?></textarea>
                </div>
                
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label class="block mb-2 font-medium">Personality Type</label>
                    <input type="text" name="personality" value="<?php echo htmlspecialchars($profile['personality']); ?>" 
                           class="w-full p-3 bg-gray-700 rounded">
                  </div>
                  <div>
                    <label class="block mb-2 font-medium">Occupation</label>
                    <input type="text" name="job" value="<?php echo htmlspecialchars($profile['job']); ?>" 
                           class="w-full p-3 bg-gray-700 rounded">
                  </div>
                </div>
                
                <div>
                  <label class="block mb-2 font-medium">Hobbies & Interests</label>
                  <textarea name="hobbies" class="w-full p-3 bg-gray-700 rounded"><?php echo htmlspecialchars($profile['hobbies']); ?></textarea>
                </div>
                
                <div>
                  <label class="block mb-2 font-medium">What You're Looking For</label>
                  <textarea name="love" class="w-full p-3 bg-gray-700 rounded"><?php echo htmlspecialchars($profile['love']); ?></textarea>
                </div>
                
                <button type="submit" class="px-6 py-3 bg-purple-600 rounded-lg hover:bg-purple-700 font-medium">
                  Save Profile
                </button>
              </form>
            <?php else: ?>
              <div class="space-y-4">
                <p class="text-lg"><?php echo nl2br(htmlspecialchars($profile['bio'])); ?></p>
                
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <h3 class="font-bold text-purple-300">Personality</h3>
                    <p><?php echo $profile['personality'] ? htmlspecialchars($profile['personality']) : 'Not specified'; ?></p>
                  </div>
                  <div>
                    <h3 class="font-bold text-purple-300">Occupation</h3>
                    <p><?php echo $profile['job'] ? htmlspecialchars($profile['job']) : 'Not specified'; ?></p>
                  </div>
                </div>
                
                <div>
                  <h3 class="font-bold text-purple-300">Hobbies & Interests</h3>
                  <p><?php echo $profile['hobbies'] ? nl2br(htmlspecialchars($profile['hobbies'])) : 'Not specified'; ?></p>
                </div>
                
                <div>
                  <h3 class="font-bold text-purple-300">Looking For</h3>
                  <p><?php echo $profile['love'] ? nl2br(htmlspecialchars($profile['love'])) : 'Not specified'; ?></p>
                </div>
              </div>
            <?php endif; ?>
          </div>
        </div>
        
        <!-- Media Section -->
        <div class="lg:w-1/3 space-y-6">
          <?php if ($profile['video']): ?>
            <div class="bg-gray-800 p-4 rounded-lg">
              <h2 class="text-xl font-bold mb-3">Video</h2>
              <div class="aspect-w-16 aspect-h-9">
                <iframe src="<?php echo htmlspecialchars($profile['video']); ?>" 
                        frameborder="0" allowfullscreen
                        class="w-full h-64 rounded"></iframe>
              </div>
            </div>
          <?php endif; ?>
          
          <?php if ($profile['song']): ?>
            <div class="bg-gray-800 p-4 rounded-lg">
              <h2 class="text-xl font-bold mb-3">Favorite Music</h2>
              <?php if ($profile['song_type'] === 'spotify'): ?>
                <iframe src="https://open.spotify.com/embed/track/<?php echo htmlspecialchars($profile['song']); ?>" 
                        width="100%" height="80" frameborder="0" 
                        allowtransparency="true" allow="encrypted-media"
                        class="rounded"></iframe>
              <?php else: ?>
                <p class="text-lg"><?php echo htmlspecialchars($profile['song']); ?></p>
              <?php endif; ?>
            </div>
          <?php endif; ?>
          
          <?php if ($profile['notes'] && $isOwnProfile): ?>
            <div class="bg-gray-800 p-4 rounded-lg">
              <h2 class="text-xl font-bold mb-3">Private Notes</h2>
              <textarea name="notes" class="w-full p-3 bg-gray-700 rounded h-40"><?php echo htmlspecialchars($profile['notes']); ?></textarea>
            </div>
          <?php endif; ?>
        </div>
      </div>
    <?php else: ?>
      <div class="bg-gray-800 p-6 rounded-lg text-center">
        <h1 class="text-3xl font-bold mb-4">Profile Not Found</h1>
        <p class="text-lg">The profile you're looking for doesn't exist or has been removed.</p>
        <a href="index.php" class="mt-4 inline-block px-6 py-2 bg-purple-600 rounded-lg hover:bg-purple-700">
          Return Home
        </a>
      </div>
    <?php endif; ?>
  </div>
</body>
</html>