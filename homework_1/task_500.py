class Solution:
    def findWords(self, words: list[str]) -> list[str]:
        rows, ans = ["qwertyuiop", "asdfghjkl", "zxcvbnm"], []
        for word in words:
            a = {n for i in word for n in range(3) if i.lower() in rows[n]}
            if len(a) == 1:
                ans.append(word)
        return ans
