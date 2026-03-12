import edge_tts
import asyncio


async def vocie(text):
    c = edge_tts.Communicate(text,"en-IE-EmilyNeural")
    await c.save("voice.mp3")
    return
    
asyncio.run(vocie("nigga get a job"))
    