// Retired deliberately: model access now stays in the user's signed-in iOS apps.
export async function POST(){return Response.json({error:'Use the configured iOS Shortcut. Model API billing is disabled in Local Sandbox.'},{status:410});}
