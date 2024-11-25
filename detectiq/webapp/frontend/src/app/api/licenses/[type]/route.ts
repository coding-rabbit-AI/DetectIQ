import { NextRequest, NextResponse } from "next/server";
import fs from "fs/promises";
import path from "path";

export async function GET(
  request: NextRequest,
  { params }: { params: { type: string } }
) {
  try {
    const type = params.type;
    let content = "";

    // Get the project root directory by going up to DetectIQ/detectiq
    const projectRoot = path.join(process.cwd(), '..', '..', '..', 'detectiq');
    console.log('Project Root:', projectRoot); // Debug log
    
    switch (type) {
      case "sigma": {
        const filePath = path.join(projectRoot, "licenses", "sigma", "drl.txt");
        console.log('Sigma License Path:', filePath); // Debug log
        content = await fs.readFile(filePath, "utf-8");
        break;
      }
      case "yara": {
        const filePath = path.join(projectRoot, "licenses", "yara", "yaraforge.txt");
        console.log('YARA License Path:', filePath); // Debug log
        content = await fs.readFile(filePath, "utf-8");
        break;
      }
      case "snort": {
        const snortDir = path.join(projectRoot, "licenses", "snort");
        console.log('Snort License Dir:', snortDir); // Debug log
        const files = ["LICENSE.txt", "AUTHORS.txt", "VRT-License.txt"];
        const contents = await Promise.all(
          files.map(async (file) => {
            const filePath = path.join(snortDir, file);
            console.log('Reading Snort file:', filePath); // Debug log
            try {
              const content = await fs.readFile(filePath, "utf-8");
              return `=== ${file} ===\n\n${content}\n\n`;
            } catch (error) {
              console.error(`Error reading ${file}:`, error);
              return `=== ${file} ===\n\nLicense file not found\n\n`;
            }
          })
        );
        content = contents.join("\n");
        break;
      }
      default:
        console.log('Invalid license type:', type); // Debug log
        return new NextResponse("Invalid license type", { status: 400 });
    }

    if (!content) {
      console.log('No content found for type:', type); // Debug log
      throw new Error(`No content found for ${type}`);
    }

    return new NextResponse(content, {
      headers: {
        'Content-Type': 'text/plain',
      },
    });
  } catch (error) {
    console.error("Error reading license file:", error);
    // Return more specific error message with path information
    return new NextResponse(
      `License content unavailable: ${error.message}\nProject Root: ${process.cwd()}`, 
      { status: 500 }
    );
  }
} 