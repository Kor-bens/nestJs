import { Get, Controller, Render } from '@nestjs/common';

@Controller()
export class AppController {
  @Get()
  @Render('index')
  root() {
    return { message: 'Hello worldaaaa!',
             navbar: ` <nav>
             <ul>
               <li><a href="#">Accueil</a></li>
               <li><a href="#">Menu</a></li>
               <li><a href="#">Photos</a></li>
             </ul>
           </nav>` };
  }
}